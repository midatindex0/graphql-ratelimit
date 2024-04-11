//! A simple per-field graphql ratelimiter library. Meant to be used as middleware.
//! ```
//! use graphql_ratelimit::{Ratelimit, RatelimitResult};
//! use std::time::Duration;
//!
//! let limiter = Ratelimit::default()
//!     .query(|m| {
//!         m.field("me", |f| {
//!             f.rate(5.0, Duration::from_secs(10))
//!                 .field("posts", |q| q.cost(3.0))
//!         })
//!     })
//!     .mutation(|m| {
//!         m.field("login", |f| f.rate(4.0, Duration::from_secs(40)))
//!             .field("createUser", |f| {
//!                 f.rate(3.0, Duration::from_secs(30)).cost(2.0)
//!             })
//!     });
//!
//! match limiter.execute(r#"mutation { login(email: "testmail@example.com", password: "Dummy password") }"#,
//!     "127.0.0.1".into()).unwrap() {
//!     RatelimitResult::Pass(tokens) => println!("Successful. {tokens} tokens left."),
//!     RatelimitResult::Block(duration) => println!("Wait {duration:?} before making next
//!     request."),
//! };
//!
//! limiter.cleanup();
//! ```

#[cfg(feature = "mem")]
use flurry::HashMap;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use std::{cmp::max, fmt::Display, time::Duration};

use apollo_parser::cst::{CstChildren, Selection};

pub struct Ratelimit<'a, S: StorageBackend, R: RatelimitBackend> {
    query_ratelimit: Field<'a>,
    mutation_ratelimit: Field<'a>,
    subscription_ratelimit: Field<'a>,
    storage_backend: S,
    ratelimit_backend: R,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    ParserError,
    BackendError,
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParserError => f.write_str("Parser Error"),
            Self::BackendError => f.write_str("Backend Error"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(feature = "mem-token-bucket")]
impl<'a> Default for Ratelimit<'a, InMemoryBackend, TokenBucket> {
    fn default() -> Self {
        Ratelimit {
            query_ratelimit: Field {
                field_name: "query",
                sub_fields: HashMap::new(),
                rate: (f32::MAX, Duration::from_secs(5)),
                cost: 1.0,
            },
            mutation_ratelimit: Field {
                field_name: "mutation",
                sub_fields: HashMap::new(),
                rate: (f32::MAX, Duration::from_secs(5)),
                cost: 1.0,
            },
            subscription_ratelimit: Field {
                field_name: "subscription",
                sub_fields: HashMap::new(),
                rate: (f32::MAX, Duration::from_secs(5)),
                cost: 1.0,
            },

            storage_backend: InMemoryBackend::new(),
            ratelimit_backend: TokenBucket {},
        }
    }
}

#[cfg(feature = "mem")]
impl<'a, R: RatelimitBackend> Ratelimit<'a, InMemoryBackend, R> {
    /// Caller must periodiclly and responsible call this to clean up filled buckets.
    /// Must be called every "time it takes to fill all buckets" interval or more depnding
    /// on traffic or memory available.
    pub fn cleanup(&self) {
        self.storage_backend
            .cleanup(self.get_longest_limit_duration())
    }
}

impl<'a, S: StorageBackend, R: RatelimitBackend> Ratelimit<'a, S, R> {
    /// Create a new Ratelimit with a [StorageBackend] and [RatelimitBackend].
    /// Use [Ratelimit::default] for an in-memory backend.
    pub fn new(storage_backend: S, ratelimit_backend: R) -> Self {
        Ratelimit {
            query_ratelimit: Field {
                field_name: "query",
                sub_fields: HashMap::new(),
                rate: (f32::MAX, Duration::from_secs(5)),
                cost: 1.0,
            },
            mutation_ratelimit: Field {
                field_name: "mutation",
                sub_fields: HashMap::new(),
                rate: (f32::MAX, Duration::from_secs(5)),
                cost: 1.0,
            },
            subscription_ratelimit: Field {
                field_name: "subscription",
                sub_fields: HashMap::new(),
                rate: (f32::MAX, Duration::from_secs(5)),
                cost: 1.0,
            },

            storage_backend,
            ratelimit_backend,
        }
    }

    /// Configure the query ratelimit.
    /// # Example
    /// ```
    /// # use graphql_ratelimit::Ratelimit;
    /// # use std::time::Duration;
    ///
    /// let limiter = Ratelimit::default().query(|q| q.rate(10.0, Duration::from_secs(10)));
    /// ```
    pub fn query(mut self, query_ratelimit_builder: impl FnOnce(Field) -> Field) -> Self {
        self.query_ratelimit = query_ratelimit_builder(self.query_ratelimit);
        self
    }

    /// Configure the mutation ratelimit.
    /// Example
    /// ```
    /// # use graphql_ratelimit::Ratelimit;
    /// # use std::time::Duration;
    ///
    /// let limiter = Ratelimit::default().mutation(|m| m.rate(5.0, Duration::from_secs(10)));
    /// ```
    pub fn mutation(mut self, mutation_ratelimit_builder: impl FnOnce(Field) -> Field) -> Self {
        self.mutation_ratelimit = mutation_ratelimit_builder(self.mutation_ratelimit);
        self
    }

    /// Configure the subscription ratelimit.
    /// # Example
    /// ```
    /// # use graphql_ratelimit::Ratelimit;
    /// # use std::time::Duration;
    ///
    /// let limiter = Ratelimit::default().subscription(|s| s.rate(3.0, Duration::from_secs(9)));
    /// ```
    pub fn subscription(
        mut self,
        subscription_ratelimit_builder: impl FnOnce(Field) -> Field,
    ) -> Self {
        self.subscription_ratelimit = subscription_ratelimit_builder(self.subscription_ratelimit);
        self
    }

    #[cfg(not(feature = "async"))]
    /// Execute one request
    /// Takes graphql query body and an unique identifier, might be ip or header
    pub fn execute(
        &self,
        req: impl AsRef<str>,
        identifier: impl AsRef<str>,
    ) -> Result<RatelimitResult, Error> {
        let identifier = identifier.as_ref().to_owned();

        let mut min_tokens = f32::MAX;
        let req = req.as_ref();

        let ctx = apollo_parser::Parser::new(req).parse();

        if ctx.errors().len() > 0 {
            return Err(Error::ParserError);
        }

        for def in ctx.document().definitions() {
            if let apollo_parser::cst::Definition::OperationDefinition(op) = def {
                if let Some(op_type) = op.operation_type() {
                    if let Some(_) = op_type.query_token() {
                        let identifier = format!("{}-query", &identifier);

                        match self.storage_backend.update(
                            &identifier,
                            self.query_ratelimit.rate.0,
                            self.query_ratelimit.rate.1,
                            |mut bucket| {
                                self.ratelimit_backend.aquire(
                                    &mut bucket,
                                    self.query_ratelimit.cost,
                                    self.query_ratelimit.rate,
                                )
                            },
                        )? {
                            RatelimitResult::Pass(t) => {
                                if t < min_tokens {
                                    min_tokens = t;
                                }
                                if let Some(selection_set) = op.selection_set() {
                                    match self.aquire_token_recursive(
                                        selection_set.selections(),
                                        &identifier,
                                        &self.query_ratelimit,
                                    )? {
                                        RatelimitResult::Pass(t) => {
                                            if t < min_tokens {
                                                min_tokens = t;
                                            }
                                        }
                                        RatelimitResult::Block(d) => {
                                            return Ok(RatelimitResult::Block(d));
                                        }
                                    }
                                }
                            }
                            RatelimitResult::Block(d) => {
                                return Ok(RatelimitResult::Block(d));
                            }
                        }
                    }

                    if let Some(_) = op_type.mutation_token() {
                        let identifier = format!("{}-mutation", &identifier);

                        match self.storage_backend.update(
                            &identifier,
                            self.mutation_ratelimit.rate.0,
                            self.mutation_ratelimit.rate.1,
                            |mut bucket| {
                                self.ratelimit_backend.aquire(
                                    &mut bucket,
                                    self.mutation_ratelimit.cost,
                                    self.mutation_ratelimit.rate,
                                )
                            },
                        )? {
                            RatelimitResult::Pass(t) => {
                                if t < min_tokens {
                                    min_tokens = t;
                                }

                                if let Some(selection_set) = op.selection_set() {
                                    match self.aquire_token_recursive(
                                        selection_set.selections(),
                                        &identifier,
                                        &self.mutation_ratelimit,
                                    )? {
                                        RatelimitResult::Pass(t) => {
                                            if t < min_tokens {
                                                min_tokens = t;
                                            }
                                        }
                                        RatelimitResult::Block(d) => {
                                            return Ok(RatelimitResult::Block(d));
                                        }
                                    }
                                }
                            }
                            RatelimitResult::Block(d) => {
                                return Ok(RatelimitResult::Block(d));
                            }
                        }
                    }

                    if let Some(_) = op_type.subscription_token() {
                        let identifier = format!("{}-subscription", &identifier);
                        match self.storage_backend.update(
                            &identifier,
                            self.subscription_ratelimit.rate.0,
                            self.subscription_ratelimit.rate.1,
                            |mut bucket| {
                                self.ratelimit_backend.aquire(
                                    &mut bucket,
                                    self.subscription_ratelimit.cost,
                                    self.subscription_ratelimit.rate,
                                )
                            },
                        )? {
                            RatelimitResult::Pass(t) => {
                                if t < min_tokens {
                                    min_tokens = t;
                                }
                                if let Some(selection_set) = op.selection_set() {
                                    match self.aquire_token_recursive(
                                        selection_set.selections(),
                                        &identifier,
                                        &self.subscription_ratelimit,
                                    )? {
                                        RatelimitResult::Pass(t) => {
                                            if t < min_tokens {
                                                min_tokens = t;
                                            }
                                        }
                                        RatelimitResult::Block(d) => {
                                            return Ok(RatelimitResult::Block(d));
                                        }
                                    }
                                }
                            }
                            RatelimitResult::Block(d) => {
                                return Ok(RatelimitResult::Block(d));
                            }
                        }
                    }
                }
            }
        }

        Ok(RatelimitResult::Pass(min_tokens))
    }

    #[cfg(feature = "async")]
    /// Execute one request
    /// Takes graphql query body and an unique identifier, might be ip or header
    pub async fn execute(
        &self,
        req: impl AsRef<str>,
        identifier: impl AsRef<str>,
    ) -> Result<RatelimitResult, Error> {
        let identifier = identifier.as_ref().to_owned();

        let mut min_tokens = f32::MAX;
        let req = req.as_ref();

        let ctx = apollo_parser::Parser::new(req).parse();

        if ctx.errors().len() > 0 {
            return Err(Error::ParserError);
        }

        for def in ctx.document().definitions() {
            if let apollo_parser::cst::Definition::OperationDefinition(op) = def {
                if let Some(op_type) = op.operation_type() {
                    if let Some(_) = op_type.query_token() {
                        let identifier = format!("{}-query", &identifier);

                        match self
                            .storage_backend
                            .update(
                                &identifier,
                                self.query_ratelimit.rate.0,
                                self.query_ratelimit.rate.1,
                                |mut bucket| {
                                    self.ratelimit_backend.aquire(
                                        &mut bucket,
                                        self.query_ratelimit.cost,
                                        self.query_ratelimit.rate,
                                    )
                                },
                            )
                            .await?
                        {
                            RatelimitResult::Pass(t) => {
                                if t < min_tokens {
                                    min_tokens = t;
                                }
                                if let Some(selection_set) = op.selection_set() {
                                    match self
                                        .aquire_token_recursive(
                                            selection_set.selections(),
                                            &identifier,
                                            &self.query_ratelimit,
                                        )
                                        .await?
                                    {
                                        RatelimitResult::Pass(t) => {
                                            if t < min_tokens {
                                                min_tokens = t;
                                            }
                                        }
                                        RatelimitResult::Block(d) => {
                                            return Ok(RatelimitResult::Block(d));
                                        }
                                    }
                                }
                            }
                            RatelimitResult::Block(d) => {
                                return Ok(RatelimitResult::Block(d));
                            }
                        }
                    }

                    if let Some(_) = op_type.mutation_token() {
                        let identifier = format!("{}-mutation", &identifier);

                        match self
                            .storage_backend
                            .update(
                                &identifier,
                                self.mutation_ratelimit.rate.0,
                                self.mutation_ratelimit.rate.1,
                                |mut bucket| {
                                    self.ratelimit_backend.aquire(
                                        &mut bucket,
                                        self.mutation_ratelimit.cost,
                                        self.mutation_ratelimit.rate,
                                    )
                                },
                            )
                            .await?
                        {
                            RatelimitResult::Pass(t) => {
                                if t < min_tokens {
                                    min_tokens = t;
                                }

                                if let Some(selection_set) = op.selection_set() {
                                    match self
                                        .aquire_token_recursive(
                                            selection_set.selections(),
                                            &identifier,
                                            &self.mutation_ratelimit,
                                        )
                                        .await?
                                    {
                                        RatelimitResult::Pass(t) => {
                                            if t < min_tokens {
                                                min_tokens = t;
                                            }
                                        }
                                        RatelimitResult::Block(d) => {
                                            return Ok(RatelimitResult::Block(d));
                                        }
                                    }
                                }
                            }
                            RatelimitResult::Block(d) => {
                                return Ok(RatelimitResult::Block(d));
                            }
                        }
                    }

                    if let Some(_) = op_type.subscription_token() {
                        let identifier = format!("{}-subscription", &identifier);
                        match self
                            .storage_backend
                            .update(
                                &identifier,
                                self.subscription_ratelimit.rate.0,
                                self.subscription_ratelimit.rate.1,
                                |mut bucket| {
                                    self.ratelimit_backend.aquire(
                                        &mut bucket,
                                        self.subscription_ratelimit.cost,
                                        self.subscription_ratelimit.rate,
                                    )
                                },
                            )
                            .await?
                        {
                            RatelimitResult::Pass(t) => {
                                if t < min_tokens {
                                    min_tokens = t;
                                }
                                if let Some(selection_set) = op.selection_set() {
                                    match self
                                        .aquire_token_recursive(
                                            selection_set.selections(),
                                            &identifier,
                                            &self.subscription_ratelimit,
                                        )
                                        .await?
                                    {
                                        RatelimitResult::Pass(t) => {
                                            if t < min_tokens {
                                                min_tokens = t;
                                            }
                                        }
                                        RatelimitResult::Block(d) => {
                                            return Ok(RatelimitResult::Block(d));
                                        }
                                    }
                                }
                            }
                            RatelimitResult::Block(d) => {
                                return Ok(RatelimitResult::Block(d));
                            }
                        }
                    }
                }
            }
        }

        Ok(RatelimitResult::Pass(min_tokens))
    }

    #[cfg(not(feature = "async"))]
    fn aquire_token_recursive(
        &self,
        selections: CstChildren<Selection>,
        identifier: &str,
        ratelimit_field: &Field,
    ) -> Result<RatelimitResult, Error> {
        let mut min_tokens = f32::MAX;
        for selection in selections {
            if let apollo_parser::cst::Selection::Field(field) = selection {
                if let Some(name) = field.name() {
                    if let Some(f) = ratelimit_field
                        .sub_fields
                        .get(name.text().as_str(), &ratelimit_field.sub_fields.guard())
                    {
                        let identifier = format!("{}-{}", &identifier, f.field_name);

                        match self.storage_backend.update(
                            &identifier,
                            f.rate.0,
                            f.rate.1,
                            |mut bucket| self.ratelimit_backend.aquire(&mut bucket, f.cost, f.rate),
                        )? {
                            RatelimitResult::Pass(t) => {
                                if t < min_tokens {
                                    min_tokens = t;
                                }

                                if let Some(selection_set) = field.selection_set() {
                                    self.aquire_token_recursive(
                                        selection_set.selections(),
                                        &identifier,
                                        f,
                                    )?;
                                }
                            }
                            RatelimitResult::Block(d) => {
                                return Ok(RatelimitResult::Block(d));
                            }
                        }
                    }
                }
            }
        }

        Ok(RatelimitResult::Pass(min_tokens))
    }

    #[cfg(feature = "async")]
    fn aquire_token_recursive<'r>(
        &'r self,
        selections: CstChildren<Selection>,
        identifier: &'r str,
        ratelimit_field: &'r Field,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<RatelimitResult, Error>> + 'r>>
    {
        Box::pin(async move {
            let mut min_tokens = f32::MAX;
            for selection in selections {
                if let apollo_parser::cst::Selection::Field(field) = selection {
                    if let Some(name) = field.name() {
                        if let Some(f) = ratelimit_field
                            .sub_fields
                            .get(name.text().as_str(), &ratelimit_field.sub_fields.guard())
                        {
                            let identifier = format!("{}-{}", &identifier, f.field_name);

                            match self
                                .storage_backend
                                .update(&identifier, f.rate.0, f.rate.1, |mut bucket| {
                                    self.ratelimit_backend.aquire(&mut bucket, f.cost, f.rate)
                                })
                                .await?
                            {
                                RatelimitResult::Pass(t) => {
                                    if t < min_tokens {
                                        min_tokens = t;
                                    }

                                    if let Some(selection_set) = field.selection_set() {
                                        self.aquire_token_recursive(
                                            selection_set.selections(),
                                            &identifier,
                                            f,
                                        )
                                        .await?;
                                    }
                                }
                                RatelimitResult::Block(d) => {
                                    return Ok(RatelimitResult::Block(d));
                                }
                            }
                        }
                    }
                }
            }

            Ok(RatelimitResult::Pass(min_tokens))
        })
    }

    /// Returns the duration after which all buckers will be filled. Useful for cleanup.
    pub fn get_longest_limit_duration(&self) -> Duration {
        max(
            max(
                Self::find_max_duration_recursive(&self.query_ratelimit),
                Self::find_max_duration_recursive(&self.mutation_ratelimit),
            ),
            Self::find_max_duration_recursive(&self.subscription_ratelimit),
        )
    }

    fn find_max_duration_recursive(f: &Field) -> Duration {
        let mut max = f.rate.1;
        let guard = f.sub_fields.guard();
        for sub_f in f.sub_fields.values(&guard) {
            if sub_f.rate.1 > max {
                max = sub_f.rate.1;
            }
            let ms = Self::find_max_duration_recursive(&sub_f);
            if ms > max {
                max = ms;
            }
        }
        max
    }
}

#[derive(Debug)]
pub struct Field<'a> {
    field_name: &'a str,
    sub_fields: HashMap<&'a str, Field<'a>>,
    rate: (f32, Duration),
    cost: f32,
}

impl<'a> Field<'a> {
    /// Set the rate limit in the formats "tokens per duration".
    pub fn rate(mut self, tokens: f32, per: Duration) -> Self {
        self.rate = (tokens, per);
        self
    }

    /// Tokens the field consumes on 1 request.
    pub fn cost(mut self, cost: f32) -> Self {
        self.cost = cost;
        self
    }

    /// Add a sub-field
    pub fn field(
        self,
        field_name: &'a str,
        query_field_builder: impl FnOnce(Field) -> Field,
    ) -> Self {
        let mut fb = Field {
            field_name,
            sub_fields: HashMap::new(),
            rate: self.rate,
            cost: self.cost,
        };
        fb = query_field_builder(fb);
        let guard = self.sub_fields.guard();
        self.sub_fields.insert(fb.field_name, fb, &guard);
        drop(guard);
        self
    }
}

pub trait StorageBackend {
    /// Update must create a new bucket if it doesn't exist,
    /// then call the calc function with a mutable borrow of that bucket.
    /// Save the mutated bucket.
    /// Finally bubble up the return value of calc or any error.
    /// `ttl` can be used to set expiery of the bucket.
    #[cfg(not(feature = "async"))]
    fn update(
        &self,
        identifier: &str,
        default_tokens: f32,
        ttl: Duration,
        calc: impl Fn(&mut Bucket) -> RatelimitResult,
    ) -> Result<RatelimitResult, Error>;

    #[cfg(feature = "async")]
    fn update(
        &self,
        identifier: &str,
        default_tokens: f32,
        ttl: Duration,
        calc: impl Fn(&mut Bucket) -> RatelimitResult,
    ) -> impl std::future::Future<Output = Result<RatelimitResult, Error>>;
}

#[cfg(feature = "mem")]
/// Simple in-memory backend. Uses flurry::HashMap under the hood.
#[derive(Debug)]
pub struct InMemoryBackend {
    map: HashMap<String, Bucket>,
}

#[cfg(not(feature = "serde"))]
#[derive(Debug, Clone, Copy)]
pub struct Bucket {
    pub last_hit: OffsetDateTime,
    pub tokens_left: f32,
}

#[cfg(feature = "serde")]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Bucket {
    pub last_hit: OffsetDateTime,
    pub tokens_left: f32,
}

#[cfg(feature = "mem")]
impl InMemoryBackend {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
}

#[cfg(feature = "mem")]
impl InMemoryBackend {
    fn cleanup(&self, ttl: Duration) {
        let guard = self.map.guard();
        self.map.retain(
            |_, f| !(OffsetDateTime::now_utc() - f.last_hit > ttl),
            &guard,
        );
    }
}

#[cfg(feature = "mem")]
impl StorageBackend for InMemoryBackend {
    #[cfg(not(feature = "async"))]
    fn update(
        &self,
        identifier: &str,
        default_tokens: f32,
        _: Duration,
        calc: impl Fn(&mut Bucket) -> RatelimitResult,
    ) -> Result<RatelimitResult, Error> {
        let guard = self.map.guard();
        let _ = self.map.try_insert(
            identifier.to_string(),
            Bucket {
                last_hit: OffsetDateTime::now_utc(),
                tokens_left: default_tokens,
            },
            &guard,
        );

        let mut result = RatelimitResult::Pass(f32::MAX);
        self.map
            .compute_if_present(
                identifier,
                |_, bucket| {
                    let mut bucket = bucket.clone();
                    result = calc(&mut bucket);
                    Some(bucket)
                },
                &guard,
            )
            .ok_or(Error::BackendError)?;

        Ok(result)
    }

    #[cfg(feature = "async")]
    async fn update(
        &self,
        identifier: &str,
        default_tokens: f32,
        _: Duration,
        calc: impl Fn(&mut Bucket) -> RatelimitResult,
    ) -> Result<RatelimitResult, Error> {
        let guard = self.map.guard();
        let _ = self.map.try_insert(
            identifier.to_string(),
            Bucket {
                last_hit: OffsetDateTime::now_utc(),
                tokens_left: default_tokens,
            },
            &guard,
        );

        let mut result = RatelimitResult::Pass(f32::MAX);
        self.map
            .compute_if_present(
                identifier,
                |_, bucket| {
                    let mut bucket = bucket.clone();
                    result = calc(&mut bucket);
                    Some(bucket)
                },
                &guard,
            )
            .ok_or(Error::BackendError)?;

        Ok(result)
    }
}

pub trait RatelimitBackend {
    /// Must calculate if a request gets ratelimited and mutate Bucket to represent the consumed
    /// state.
    fn aquire(&self, bucket: &mut Bucket, cost: f32, rate: (f32, Duration)) -> RatelimitResult;
}

/// Simple token bucket implementation.
#[cfg(feature = "token-bucket")]
pub struct TokenBucket;

#[cfg(feature = "token-bucket")]
impl RatelimitBackend for TokenBucket {
    fn aquire(&self, bucket: &mut Bucket, cost: f32, rate: (f32, Duration)) -> RatelimitResult {
        let current_time = OffsetDateTime::now_utc();
        let tokens_to_add =
            (current_time - bucket.last_hit).as_seconds_f32() / rate.1.as_secs_f32() * rate.0;
        bucket.tokens_left += tokens_to_add;
        if bucket.tokens_left > rate.0 {
            bucket.tokens_left = rate.0;
        }
        bucket.last_hit = current_time;
        if bucket.tokens_left >= cost {
            bucket.tokens_left -= cost;
            return RatelimitResult::Pass(bucket.tokens_left / cost);
        }
        RatelimitResult::Block(Duration::from_secs_f32(
            (cost - bucket.tokens_left) * rate.1.as_secs_f32() / rate.0,
        ))
    }
}

/// Represents whether a request gets ratelimited or not.
/// Pass contains the numbers of requests left before ratelimit (tokens_left/cost)
/// Block contains the time to wait before next request is successful
#[derive(Debug)]
pub enum RatelimitResult {
    Pass(f32),
    Block(Duration),
}

#[cfg(test)]
#[cfg(feature = "mem-token-bucket")]
#[cfg(not(feature = "mem-token-bucket"))]
#[test]
fn test_ratelimit() {
    let limiter = Ratelimit::default()
        .query(|m| {
            m.field("me", |f| {
                f.rate(5.0, Duration::from_secs(10))
                    .field("posts", |q| q.cost(3.0))
            })
        })
        .mutation(|m| {
            m.field("login", |f| f.rate(4.0, Duration::from_secs(40)))
                .field("createUser", |f| {
                    f.rate(3.0, Duration::from_secs(30)).cost(2.0)
                })
        });

    assert_eq!(
        (0..=10)
            .map(|_| {
                std::thread::sleep(Duration::from_secs_f32(1.0));
                limiter.execute(
                r#"mutation { login(email: "testmail@example.com", password: "Dummy password") }"#,
                "127.0.0.1".into(),
            ).unwrap()
            })
            .filter(|x| match x {
                RatelimitResult::Pass(_) => true,
                _ => false,
            })
            .collect::<Vec<_>>()
            .len(),
        5
    );

    limiter.cleanup();
}

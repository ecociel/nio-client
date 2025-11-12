#[cfg(test)]
mod check {
    use http::Uri;

    use check_client::auth::CheckResult;
    use check_client::{CheckClient, Permission};
    use check_client::{Namespace, Obj, UserId};
    // #[tokio::test]
    // #[serial]
    // #[ignore]
    // async fn add_tuple() {
    //     let nio_check_uri = env!("NIO_CHECK_URI");
    //     let uri = Uri::try_from(nio_check_uri).unwrap();
    //     let mut check_client = CheckClient::create(uri).await.unwrap();
    //     let tuple = Tuple {
    //         ns: Namespace("firm".to_string()),
    //         obj: Obj("ashwin".to_string()),
    //         role: Rel("editor".to_string()),
    //         sbj: User::UserId("xxx".to_string()),
    //     };
    //     let ts = check_client.add_one(tuple).await.unwrap();
    //     dbg!("tuple saved at {}", ts);
    // }
    //
    // #[tokio::test]
    // #[serial]
    // #[ignore]
    // async fn add_token_tuple() {
    //     pub fn token_tuple(
    //         identity: impl Into<String>,
    //         now: DateTime<Utc>,
    //     ) -> (String, Tuple, Condition) {
    //         let token: String = "123456".to_string();
    //         let tuple = Tuple {
    //             ns: Namespace("token".to_string()),
    //             obj: Obj::from_str(&token)
    //                 .expect("nanoid should produce a valid string for an object"), // TODO: fix expect..
    //             rel: Rel("is".to_string()),
    //             sbj: User::UserId(identity.into()),
    //         };
    //         let condition = Condition::Expires(now.add(TimeDelta::minutes(120)));
    //         (token, tuple, condition)
    //     }
    //     let nio_check_uri = env!("NIO_CHECK_URI");
    //     let uri = Uri::try_from(nio_check_uri).unwrap();
    //     let mut check_client = CheckClient::create(uri).await.unwrap();
    //     // Pass userid inside token_tuple instead of xxx to generate token for testing
    //     let (token, tuple, condition) = token_tuple("xxx".to_string(), Utc::now());
    //     let ts = check_client
    //         .save_tuple(tuple, Some(condition))
    //         .await
    //         .unwrap();
    //     dbg!("token {} generated at {}", token, ts);
    // }
    //
    // #[tokio::test]
    // #[serial]
    // #[ignore]
    // async fn add_tuple_userset() {
    //     let nio_check_uri = env!("NIO_CHECK_URI");
    //     let uri = Uri::try_from(nio_check_uri).unwrap();
    //     let mut check_client = CheckClient::create(uri).await.unwrap();
    //     let tuple = Tuple {
    //         ns: Namespace("firm".to_string()),
    //         obj: Obj("demo".to_string()),
    //         role: Rel("editor".to_string()),
    //         sbj: User::UserSet {
    //             ns: Namespace("group".to_string()),
    //             obj: Obj("nimmy".to_string()),
    //             role: Rel("member".to_string()),
    //         },
    //     };
    //     let ts = check_client.save_tuple(tuple, None).await.unwrap();
    //     dbg!("tuple saved at {}", ts);
    // }
    //
    // #[tokio::test]
    // #[serial]
    // #[ignore]
    // async fn delete_tuple() {
    //     let nio_check_uri = env!("NIO_CHECK_URI");
    //     let uri = Uri::try_from(nio_check_uri).unwrap();
    //     let mut check_client = CheckClient::create(uri).await.unwrap();
    //     let tuple = Tuple {
    //         ns: Namespace("firm".to_string()),
    //         obj: Obj("demo".to_string()),
    //         role: Rel("editor".to_string()),
    //         sbj: User::UserId("db1289eb-7c45-4efd-8878-33d4c2014749".to_string()),
    //     };
    //     let ts = check_client.delete_tuple(tuple).await.unwrap();
    //     dbg!("tuple removed at {}", ts);
    // }

    #[tokio::test]
    // #[ignore]
    async fn check() {
        let nio_check_uri = env!("NIO_CHECK_URI");
        let uri = Uri::try_from(nio_check_uri).unwrap();
        let mut check_client = CheckClient::create(uri).await.unwrap();

        let ns = Namespace("customer".to_string());
        let obj = Obj("acme".to_string());
        let per = Permission("customer.update");
        //let userid = UserId("734962c4-4c27-4c81-9d5f-7ddd5ae57f42".to_string());
        let userid = UserId("abcdef".to_string());

        let res = check_client
            .check(ns, obj, per, userid.clone(), None)
            .await
            .unwrap();
        match res {
            CheckResult::Ok(p) => println!("ok {}", p.as_str()),

            CheckResult::Forbidden(p) => println!("forbidden {}", p.as_str()),
            CheckResult::UnknownPutativeUser => println!("unknown user {:?}", userid),
        }
    }

    #[tokio::test]
    // #[ignore]
    async fn list() {
        let nio_check_uri = env!("NIO_CHECK_URI");
        let uri = Uri::try_from(nio_check_uri).unwrap();
        let mut check_client = CheckClient::create(uri).await.unwrap();

        let ns = Namespace("customer".to_string());
        let obj = Obj("customer.get".to_string());
        let userid = UserId("734962c4-4c27-4c81-9d5f-7ddd5ae57f42".to_string());

        let res = check_client.list(ns, obj, userid, None).await.unwrap();
        println!("--LIST DATA--{:#?}", res);
    }
    #[tokio::test]
    // #[ignore]
    async fn list2() {
        let nio_check_uri = env!("NIO_CHECK_URI");
        let uri = Uri::try_from(nio_check_uri).unwrap();
        let mut check_client = CheckClient::create(uri).await.unwrap();

        let ns = Namespace("customer".to_string());
        let obj = Obj("customer.get".to_string());
        let userid = UserId("151714cf-d62c-4e1f-9236-0e8ee1811b9d".to_string());

        let res = check_client.list(ns, obj, userid, None).await.unwrap();
        println!("--LIST DATA--{:#?}", res);
    }
}

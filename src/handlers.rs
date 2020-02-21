use tide::{ Request, Response, Next };

pub async fn get_packument<State>(req: Request<State>) -> String {
    let package: String = req.param("pkg").unwrap();
    format!("get packument {}", package)
}

pub async fn put_packument<State>(req: Request<State>) -> &'static str {
    "put packument"
}

pub async fn get_tarball<State>(req: Request<State>) -> &'static str {
    "get tarball"
}

pub async fn get_scoped_tarball<State>(req: Request<State>) -> &'static str {
    "get scoped tarball"
}

pub async fn post_login<State>(req: Request<State>) -> &'static str {
    "post login"

}

pub async fn get_login_poll<State>(req: Request<State>) -> &'static str {

    "get login poll"
}

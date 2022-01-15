#[tokio::main]
async fn main() {

  println!("starting");

  let ip_addr = std::env::args().nth(1).expect("send the ip address as 1st argument");
  let dir = std::env::args().nth(2).expect("send the directory as 2nd argument");

  let mut rx = r_ftp::start_server(10234);

  println!("server started on ip: {}, serving: {}", ip_addr, dir);

  loop {
    println!("waiting");

    if let Option::Some(con) = rx.recv().await {
      match con {
        Ok(mut con) => {
          con.set_self_ip_addr(&ip_addr);
          con.set_validator(validator);
          con.set_dir(&dir);

          con.start();
        },
        Err(err) => {
          println!("error: {}", err);
        }
      }
    } else {
      println!("None received, error ?");
    }
  }
}

fn validator(username: &str, password: &str) -> bool {
  println!("username: {}, password: {}", username, password);
  return username.eq("test") && password.eq("_test_");
}

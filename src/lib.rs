use std::collections::HashMap;
use std::fmt::Formatter;
use tokio::fs;
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{self, Receiver};

const ASCII_LF: u8    = b'\n';
const ASCII_CR: u8    = b'\r';
const ASCII_SPACE: u8 = b' ';

enum ErrorMessage {
  Raw(&'static str),
  Bloated(String)
}

pub struct Error {
  error_message: ErrorMessage
}

impl Error {
  fn new_raw(error_message: &'static str) -> Error {
    Error {
      error_message: ErrorMessage::Raw(error_message)
    }
  }

  fn new_bloated(error_message: String) -> Error {
    Error {
      error_message: ErrorMessage::Bloated(error_message)
    }
  }
}

impl std::fmt::Display for Error {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    match &self.error_message {
      ErrorMessage::Raw(msg) => {
        write!(f, "{}", msg)
      },
      ErrorMessage::Bloated(msg) => {
        write!(f, "{}", msg)
      }
    }
  }
}

impl From<std::num::ParseIntError> for Error {
  fn from(error: std::num::ParseIntError) -> Self {
    Error::new_bloated(format!("{:?}", error.kind()))
  }
}

impl From<tokio::io::Error> for Error {
  fn from(error: std::io::Error) -> Self {
    Error::new_bloated(format!("{}", error))
  }
}

impl From<std::str::Utf8Error> for Error {
  fn from(error: std::str::Utf8Error) -> Self {
    Error::new_bloated(format!("{}", error))
  }
}

#[derive(Debug)]
enum TransferType {
  Binary,
  Text
}

#[async_trait::async_trait]
pub trait Handler {
  async fn handle(&self, connection: &mut Connection, args: &[u8]) -> Result<(), Error>;
}

type MethodId = u64;

pub struct CwdHandler;
pub struct PwdHandler;
pub struct RestHandler;
pub struct SizeHandler;
pub struct PasvHandler;
pub struct EpsvHandler;
pub struct UserHandler;
pub struct PassHandler;
pub struct RetrHandler;
pub struct TypeHandler;
pub struct QuitHandler;
pub struct ListHandler;
pub struct NlstHandler;

#[async_trait::async_trait]
impl Handler for CwdHandler {
  async fn handle(&self, connection: &mut Connection, _: &[u8]) -> Result<(), Error> {
    // currently can't CD for security reasons
    connection.send_control_raw(b"250 Requested file action okay, completed.\r\n").await
  }
}

#[async_trait::async_trait]
impl Handler for PwdHandler {
  async fn handle(&self, connection: &mut Connection, _: &[u8]) -> Result<(), Error> {
    connection.send_control_raw(format!("200 {}\r\n", &connection.dir).as_bytes()).await
  }
}

#[async_trait::async_trait]
impl Handler for RestHandler {
  async fn handle(&self, connection: &mut Connection, args: &[u8]) -> Result<(), Error> {

    let pos = std::str::from_utf8(args)?;
    let pos = pos.parse::<usize>()?;

    println!("read_pos: {}", pos);

    connection.read_pos = pos;

    connection.send_control_raw(b"200 ok.\r\n").await
  }
}

#[async_trait::async_trait]
impl Handler for SizeHandler {
  async fn handle(&self, connection: &mut Connection, args: &[u8]) -> Result<(), Error> {

    let dir = &connection.dir;

    if let Ok(file_name) = std::str::from_utf8(args) {
      if let Ok(mut file) = File::open(format!("{}/{}", dir, file_name)).await {
        if let Ok(len) = file.seek(std::io::SeekFrom::End(0)).await {
          return connection.send_control_raw(format!("211-success\r\n{}\r\n211 END\r\n", len).as_bytes()).await;
        }
      }
    }

    return connection.send_control_raw(b"500 Syntax error, command unrecognized.\r\n").await;
  }
}

#[async_trait::async_trait]
impl Handler for PasvHandler {

  async fn handle(&self, connection: &mut Connection, _: &[u8]) -> Result<(), Error> {
    if let Some(port) = portpicker::pick_unused_port() {
      if let Ok(data_listener) = TcpListener::bind(format!("0.0.0.0:{}", port)).await {
        connection.port = port;
        connection.data_listener = Option::Some(data_listener);

        println!("port: {}", port);

        let ip = &connection.ip;
        let response = format!("227 Entering Passive Mode ({},{},{},{},{},{}).\r\n", ip[0], ip[1], ip[2], ip[3], port / 256, port % 256);

        return connection.send_control_raw(response.as_bytes()).await;
      }
    }

    return connection.send_control_raw(b"425 Can't open data connection.\r\n").await;
  }
}

#[async_trait::async_trait]
impl Handler for EpsvHandler {
  async fn handle(&self, connection: &mut Connection, _: &[u8]) -> Result<(), Error> {
    if let Some(_) = connection.data_listener {
      connection.send_control_raw(format!("229 Entering Extended Passive Mode (|||{}|)\r\n", connection.port).as_bytes()).await
    } else {
      connection.send_control_raw(b"425 Can't open data connection.\r\n").await
    }
  }
}

#[async_trait::async_trait]
impl Handler for UserHandler {
  async fn handle(&self, connection: &mut Connection, args: &[u8]) -> Result<(), Error> {

    match std::str::from_utf8(args) {
      Ok(val) => {
        connection.username = String::from(val);
        connection.send_control_raw(b"331 User name okay, need password.\r\n").await
      },
      Err(err) => {
        println!("error while parsing username: {:?}", err);
        connection.send_control_raw(b"501 Syntax error in parameters or arguments.\r\n").await
      }
    }
  }
}

#[async_trait::async_trait]
impl Handler for PassHandler {
  async fn handle(&self, connection: &mut Connection, args: &[u8]) -> Result<(), Error> {
    match std::str::from_utf8(args) {
      Ok(val) => {
        if (connection.validator)(&connection.username, val) {
          (connection.registerer)(connection);
          connection.send_control_raw(b"230 User logged in, proceed.\r\n").await
        } else {
          connection.send_control_raw(b"530 Not logged in.\r\n").await
        }
      },
      Err(err) => {
        println!("error while parsing password: {:?}", err);
        connection.send_control_raw(b"501 Syntax error in parameters or arguments.\r\n").await
      }
    }
  }
}

#[async_trait::async_trait]
impl Handler for RetrHandler {
  async fn handle(&self, connection: &mut Connection, args: &[u8]) -> Result<(), Error> {

    if let Ok(file_name) = std::str::from_utf8(args) {
      if !file_name.contains("..") {
        let dir = &connection.dir;

        let file_path = format!("{}/{}", dir, file_name);

        println!("retrieving file: {}", file_path);
        let mut file = File::open(file_path).await?;

        println!("accepting new connection");
        let mut data_connection = connection.accept_data_connection().await?;

        println!("seeking");
        file.seek(std::io::SeekFrom::Start(connection.read_pos as u64)).await?;

        connection.control_stream.write_all(b"150 File status okay; about to open data connection.\r\n").await?;

        connection.send_data(&mut file, &mut data_connection).await?;

        connection.send_control_raw(b"226 File transfer successful. Closing data connection.\r\n").await?;

        return Ok(());
      }
    }

    return connection.send_control_raw(b"550 may be file does not exist.\r\n").await;
  }
}

#[async_trait::async_trait]
impl Handler for TypeHandler {
  async fn handle(&self, connection: &mut Connection, args: &[u8]) -> Result<(), Error> {

    if 1 != args.len() {
      return connection.send_control_raw(b"500 Syntax error, command unrecognized.\r\n").await;
    }

    let arg_byte = args[0];

    if b'a' == arg_byte.to_ascii_lowercase() {
      connection.transfer_type = TransferType::Text;
      return connection.send_control_raw(b"200 Command ok.\r\n").await;
    }

    if b'i' == arg_byte.to_ascii_lowercase() {
      connection.transfer_type = TransferType::Binary;
      return connection.send_control_raw(b"200 Command ok.\r\n").await;
    }

    println!("illegal type arg: {}", arg_byte);
    return connection.send_control_raw(b"500 Syntax error, command unrecognized.\r\n").await;
  }
}

#[async_trait::async_trait]
impl Handler for QuitHandler {
  async fn handle(&self, connection: &mut Connection, _: &[u8]) -> Result<(), Error> {
    connection.send_control_raw(b"221 Closing connection\r\n").await?;
    connection.quit().await?;

    Ok(())
  }
}

#[async_trait::async_trait]
impl Handler for ListHandler {
  async fn handle(&self, connection: &mut Connection, args: &[u8]) -> Result<(), Error> {

    let sub_dir = match std::str::from_utf8(args) {
      Ok(sub_dir) => {
        println!("listing sub_dir: {}", sub_dir);
        sub_dir
      },
      Err(err) => {
        println!("error: {:?}", err);
        ""
      }
    };

    if sub_dir.contains("..") {
      return Err(Error::new_raw("cannot use .. anywhere in args"));
    }

    let dir = &format!("{}/{}", &connection.dir, sub_dir);

    println!("accepting new connection");

    let mut data_connection = connection.accept_data_connection().await?;
    let mut entries = fs::read_dir(dir).await?;

    connection.send_control_raw(b"150 File status okay; about to open data connection.\r\n").await?;

    while let Some(entry) = entries.next_entry().await? {
      let file_name = String::from(entry.file_name().to_str().unwrap());

      let file_path = format!("{}{}", dir, file_name);

      println!("{}", file_path);

      let file = File::open(file_path).await?;

      let metadata = file.metadata().await?;

      let is_dir = metadata.is_dir();
      let len = metadata.len();

      let entry_type = if is_dir { 'd' } else { '-' };

      let entry = format!("{}rw-r--r-- 1 unknown unknown {} Dec 31 00:00 {}\r\n", entry_type, len, file_name);

      connection.send_data_raw(entry.as_bytes(), &mut data_connection).await?;
    }

    connection.send_control_raw(b"226 Transfer success, Closing data connection.\r\n").await?;

    Ok(())
  }
}

#[async_trait::async_trait]
impl Handler for NlstHandler {
  async fn handle(&self, connection: &mut Connection, args: &[u8]) -> Result<(), Error> {

    let sub_dir = match std::str::from_utf8(args) {
      Ok(sub_dir) => {
        println!("listing sub_dir: {}", sub_dir);
        sub_dir
      },
      Err(err) => {
        println!("error: {:?}", err);
        ""
      }
    };

    if sub_dir.contains("..") {
      return Err(Error::new_raw("cannot use .. anywhere in args"));
    }

    let dir = &format!("{}/{}", &connection.dir, sub_dir);

    println!("accepting new connection");

    let mut data_connection = connection.accept_data_connection().await?;
    let mut entries = fs::read_dir(dir).await?;

    connection.send_control_raw(b"150 File status okay; about to open data connection.\r\n").await?;

    while let Some(entry) = entries.next_entry().await? {
      let file_name = String::from(entry.file_name().to_str().unwrap());

      let file_path = format!("{}{}", dir, file_name);

      println!("{}", file_path);

      let file = File::open(file_path).await?;

      let metadata = file.metadata().await?;

      let is_file = metadata.is_file();

      if !is_file {
        continue;
      }

      connection.send_data_raw(file_name.as_bytes(), &mut data_connection).await?;
      connection.send_data_raw(b"\r\n", &mut data_connection).await?;
    }

    connection.send_control_raw(b"226 Transfer success, Closing data connection.\r\n").await?;

    Ok(())
  }
}

pub struct Connection {
  id: u64,
  ip: [u8; 4],
  read_pos: usize,
  // todo: use this variable in retr ?
  transfer_type: TransferType,
  username: String,
  control_stream: TcpStream,
  port: u16,
  data_listener: Option<TcpListener>,
  dir: String,
  handlers: HashMap<MethodId, Box<dyn Handler + Send + Sync>>,
  registerer: fn(&mut Connection),
  validator: fn(&str, &str) -> bool
}

impl Connection {

  pub fn set_self_ip_addr(&mut self, ip: &String) {
    let ip: Vec<u8> = ip
        .split(".")
        .into_iter()
        .map(|val| {
          return val.parse::<u8>().unwrap();
        })
        .collect();

    if 4 != ip.len() {
      panic!("provide valid ip");
    }

    for i in 0..4 {
      self.ip[i] = ip[i];
    }
  }

  pub fn set_validator(&mut self, validator: fn(&str, &str) -> bool) {
    self.validator = validator;
  }

  pub fn set_registerer(&mut self, registerer: fn(&mut Connection)) {
    self.registerer = registerer;
  }

  pub fn set_dir(&mut self, dir: &String) {
    self.dir = dir.clone();
  }

  pub fn start(mut self) {

    println!("handling connection in dir: {}", self.dir);

    tokio::spawn(async move {
      match self.handle_connection().await {
        Err(err) => {
          println!("error: {}", err);
        },
        _ => {
          println!("success ?");
        }
      };

      println!("Connection closed: {}", self.id);
    });
  }

  pub fn register_handler<T>(&mut self, method: &str, handler: T)
  where
      T: Handler + Send + Sync + 'static {

    let method = method.as_bytes();
    let method = method_to_int(method);

    self.handlers.insert(method, Box::new(handler));
  }

  async fn quit(&mut self) -> Result<(), Error> {
    self.data_listener = None;

    self.control_stream.flush().await?;
    self.control_stream.shutdown().await?;

    Ok(())
  }

  async fn call_handler(&mut self, method: MethodId, args: &[u8]) {

    let handler = self.handlers.remove(&method);

    let handler = match handler {
      Some(handler) => handler,
      None => {
        // ignoring the error
        self.send_control_raw(b"500 Syntax error, command unrecognized.\r\n").await.ok();
        return;
      }
    };

    let ret_val = handler.handle(self, args).await;

    self.handlers.insert(method, handler);

    match ret_val {
      Err(err) => {
        println!("error, replying with default response: {}", err);

        // ignoring the error in this case.
        self.send_control_raw(b"500 Syntax error, command unrecognized.\r\n").await.ok();
      },
      Ok(_) => {}
    };
  }

  async fn handle_connection(&mut self) -> Result<(), Error> {
    let mut command: Vec<u8> = Vec::with_capacity(1024);

    self.send_control_raw(b"220 welcome to the ftp\r\n").await?;

    loop {
      println!("preparing for next command");

      let mut command_terminated: bool;
      let mut buf: [u8; 1024] = [0; 1024];

      loop {
        let read_len = self.control_stream.read(&mut buf).await?;

        command.extend(&buf[0..read_len]);

        println!("read_len = {}", read_len);

        if 0 == read_len {
          return Ok(());
        }

        command_terminated = read_len > 2
            && ASCII_CR == buf[read_len - 2]
            && ASCII_LF == buf[read_len - 1];

        if command_terminated {
          println!("message: {}", String::from_utf8_lossy(command.as_mut_slice()).as_ref());
        }

        if command_terminated {
          // processing command

          let (method, arg_slice) = check_and_get_command(&command);

          println!("inferred val: {:?}", method);

          self.call_handler(method, arg_slice).await;

          command.clear();
        }
      }
    }
  }

  fn new(id: u64, control_stream: TcpStream) -> Connection {
    fn default_validator(_: &str, _: &str) -> bool {
      return true;
    }

    let mut connection = Connection {
      id: id,
      ip: [0, 0, 0, 0],
      read_pos: 0,
      transfer_type: TransferType::Binary,
      username: String::from(""),
      control_stream: control_stream,
      port: 0,
      data_listener: Option::None,
      dir: String::from("."),
      handlers: HashMap::new(),
      registerer: register_all_default_handlers,
      validator: default_validator
    };

    connection.register_handler("USER", UserHandler {});
    connection.register_handler("PASS", PassHandler {});
    connection.register_handler("TYPE", TypeHandler {});
    connection.register_handler("QUIT", QuitHandler {});

    return connection;
  }

  async fn accept_data_connection(&mut self) -> Result<TcpStream, Error> {
    return match &self.data_listener {
      None => {
        Result::Err(Error::new_raw("illegal arg"))
      },
      Some(data_listener) => {
        Result::Ok(data_listener.accept().await?.0)
      }
    };
  }

  async fn send_control_raw(&mut self, input: &[u8]) -> Result<(), Error> {
    Result::Ok(self.control_stream.write_all(input).await?)
  }

  async fn send_data_raw<T>(&mut self, input: &[u8], output: &mut T) -> Result<(), Error>
  where
      T: AsyncWrite + Unpin {
    Result::Ok(output.write_all(input).await?)
  }

  async fn send_data<U, T>(&mut self, input: &mut U, output: &mut T) -> Result<(), Error>
  where
      U: AsyncRead + Unpin,
      T: AsyncWrite + Unpin {

    let mut data: [u8; 1024] = [0; 1024];

    loop {
      let read_size = input.read(&mut data).await?;
      output.write_all(&mut data[0..read_size]).await?;

      if 0 == read_size {
        break;
      }
    }

    return Result::Ok(());
  }
}

pub fn start_server(port: u16) -> Receiver<Result<Connection, Error>> {

  let (tx, rx)
      = mpsc::channel::<Result<Connection, Error>>(100);

  tokio::spawn(async move {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await;

    let listener = match listener {
      Ok(listener) => {
        listener
      },
      Err(err) => {
        println!("{}", err);
        tx.send(Result::Err(Error::from(err))).await;

        return;
      }
    };

    let mut id: u64 = 0;

    loop {
      let sock = listener.accept().await;

      let sock = match sock {
        Ok(sock) => {
          sock.0
        },
        Err(err) => {
          println!("{:?}", err);
          tx.send(Result::Err(Error::from(err))).await;

          continue;
        }
      };

      id += 1;

      tx.send(Result::Ok(Connection::new(id, sock))).await;
    }
  });

  return rx;
}

pub fn register_all_default_handlers(connection: &mut Connection) {
  connection.register_handler("CWD", CwdHandler {});
  connection.register_handler("PWD", PwdHandler {});
  connection.register_handler("REST", RestHandler {});
  connection.register_handler("SIZE", SizeHandler {});
  connection.register_handler("PASV", PasvHandler {});
  connection.register_handler("EPSV", EpsvHandler {});
  connection.register_handler("RETR", RetrHandler {});
  connection.register_handler("LIST", ListHandler {});
  connection.register_handler("NLST", NlstHandler {});
}

fn method_to_int(method: &[u8]) -> MethodId {
  const MAX_METHOD_LEN: usize = 4;

  assert!(method.len() <= MAX_METHOD_LEN);

  // knowingly using u64 where as u32 is enough for all the cases.
  let mut converted_method: MethodId = 0;

  for ch in method {
    let mut ch = *ch;

    ch.make_ascii_lowercase();

    converted_method = converted_method << 8;
    converted_method = converted_method | (ch as u64);
  }

  return converted_method;
}

fn check_and_get_command(command: &[u8]) -> (MethodId, &[u8]) {
  let len = command.len();

  if len <= 2
      || ASCII_CR != command[len - 2]
      || ASCII_LF != command[len - 1] {

    return (0, &command[0..len]);
  }

  let mut command_started = false;
  let mut command_start = 0 as usize;
  let mut command_end = len - 2;

  for i in 0..len {
    let c = command[i];

    if !command_started && ASCII_SPACE != c {
      command_started = true;
      command_start = i;
    }

    if command_started && ASCII_SPACE == c {
      command_end = i;
      break;
    }
  }

  let mut arg_started = false;
  let mut arg_start = len - 2; // 2 for cr & lf
  let arg_end = len - 2;

  for i in command_end..arg_end {
    let c = command[i];

    if !arg_started && ASCII_SPACE != c {
      arg_started = true;
      arg_start = i;
    }
  }

  return (method_to_int(&command[command_start..command_end]), &command[arg_start..arg_end]);
}

#[cfg(test)]
mod tests {
  use crate::{ASCII_CR, ASCII_LF, ASCII_SPACE};

  const C: u8 = b'c';
  const D: u8 = b'd';
  const E: u8 = b'e';
  const R: u8 = b'r';
  const T: u8 = b't';
  const W: u8 = b'w';

  #[test]
  fn test_method_to_int() {
    let method = [C, W, D];
    let key = super::method_to_int(&method);

    assert_eq!(key, 0x00_63_77_64);

    let method = [R, E, T, R];
    let key = super::method_to_int(&method);

    assert_eq!(key, 0x72_65_74_72);
  }

  #[test]
  fn test_check_and_get_command() {
    let command = [C, W];
    let (method, args) = super::check_and_get_command(&command);

    assert_eq!(method, 0);
    assert_eq!(args, [C, W]);

    let command = [C, W, ASCII_CR, ASCII_LF];
    let (method, args) = super::check_and_get_command(&command);

    assert_eq!(method, 0x00_00_63_77);
    assert_eq!(args, []);

    let command = [C, W, D, ASCII_SPACE, R, T, R, ASCII_CR, ASCII_LF];
    let (method, args) = super::check_and_get_command(&command);

    assert_eq!(method, 0x00_63_77_64);
    assert_eq!(args, [R, T, R]);

    let command = [
      C.to_ascii_uppercase(),
      W.to_ascii_uppercase(),
      D.to_ascii_lowercase(),
      ASCII_SPACE,
      R, T, R,
      ASCII_CR, ASCII_LF];

    let (method, args) = super::check_and_get_command(&command);

    assert_eq!(method, 0x00_63_77_64);
    assert_eq!(args, [R, T, R]);
  }
}

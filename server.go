package main

import ( 
  "log"
  "net/http"
  "bytes"
  "fmt"
  "io"
  "os"
  "crypto/rand"
  "crypto/sha1"
  "github.com/go-martini/martini"  
  "github.com/martini-contrib/binding"
  "github.com/martini-contrib/render"
  "menteslibres.net/gosexy/redis"
)
const saltSize = 16
const host = "127.0.0.1"
const port = uint(6379)

var client *redis.Client

type User struct {
    Username    string `form:"username" binding:"required"`
    Password   string `form:"password" binding:"required"`
}
//Using this to store the latest error message.
var lastError string

func main() {
  //Create new Martini
  m := martini.Classic()
  m.Use(render.Renderer())
  route := martini.NewRouter()

  //Route for Authenticating user via JSON Post
  route.Post("/authenticate", binding.Bind(User{}), func(r render.Render, thisUser User) {
     if UserAuthenticate(thisUser) {
      newmap := map[string]interface{}{"responseText":"success", "message": "User successfully authenticated!"} 
      r.JSON(200, newmap)
     } else {
      newmap := map[string]interface{}{"responseText":"error", "message": "User could not be authenticated!", "debugError" : lastError} 
      r.JSON(401, newmap)
     }
  })
  //Route for Creating user via JSON Post
  route.Post("/create", binding.Bind(User{}), func(r render.Render, thisUser User) {
    if UserCreate(thisUser) {
      newmap := map[string]interface{}{"responseText":"success", "message": "User successfully created!"} 
      r.JSON(200, newmap)
    } else {
      newmap := map[string]interface{}{"responseText":"error", "message": "User could not be created!", "debugError" : lastError} 
      r.JSON(200, newmap)
    }

  })
  //Default Route
  route.Get("/", func() string {
    return "Please use me via REST"
  })

  m.Action(route.Handle)
  log.Println("Waiting for REST commands...")

  //Serve HTTP if no errors.
  if err := http.ListenAndServe(":8000", m); err != nil {
    log.Fatal(err)
  }

}
func UserCreate(thisUser User) bool {
  var err error 
  var userNameExists bool
  var nextUserID string
  //Connect to Redis
  client := redis.New()
  err = client.Connect(host, port)
  username := thisUser.Username
  thisPassword := thisUser.Password
  //Make sure connection had no errors
  if err != nil {
    lastError = "Connection to Redis Failed";
    log.Fatalf("Connect failed: %s\n", err.Error())
    return false
  }
  //Search for the username in the users hash
  userNameExists, err = client.HExists("users", username);

  //If it exists exit with error message
  if userNameExists {
    lastError = "Username already exists!";
    return false
  }

  //Get the current max UserID
  nextUserID, err = client.Get("maxUserID")

  //If there is no max userID, set one. If there is one, increment it
  if err != nil {
    client.Set("maxUserID", 1)
    nextUserID, err = client.Get("maxUserID")
  } else {
    client.Incr("maxUserID")
    nextUserID, err = client.Get("maxUserID")
  }

  //Creating userID's like so, not very familar with Redis. 
  userID := "user:"+nextUserID
  password := []byte(thisPassword)
  salt := generateSalt(password);
  encryptedPassword := encryptPassword(password, salt);

  client.HSet(userID, "username", username)
  client.HSet(userID, "password", encryptedPassword)
  client.HSet(userID, "salt", salt)
  client.HSet("users", username, userID);

  client.Quit()

  return true
}

func UserAuthenticate(thisUser User) bool {
  var redisUserID string
  var redisPassword string
  var redisSalt string
  var thisPassword string


  client := redis.New()
  err := client.Connect(host, port)
  username := thisUser.Username
  thisPassword = thisUser.Password
  //Assure Redis connects
  if err != nil {
    lastError = "Connection to Redis Failed";
    log.Fatalf("Connect failed: %s\n", err.Error())
    return false
  }

  //Ger User ID and Password from Redis
  redisUserID, err = client.HGet("users", username);   
  redisPassword, err = client.HGet(redisUserID, "password");
  redisSalt, err = client.HGet(redisUserID, "salt");

  redisPasswordByte := []byte(redisPassword)

  //Salt and encrpyt the sent password
  password := []byte(thisPassword)
  salt := []byte(redisSalt)
  passwordHash := encryptPassword(password, salt)


  match := bytes.Equal(redisPasswordByte, passwordHash)
  if match == false {
    lastError = "Username or Password incorrect!"
  }
  return match
}
//Encrypt Password using provided salt
func encryptPassword(password, salt []byte) []byte{
  combination := string(salt) + string(password)
  passwordHash := sha1.New()
  io.WriteString(passwordHash, combination)
  encryptedPassword := passwordHash.Sum(nil)
  return encryptedPassword
}
//Generate a random salt
func generateSalt(secret []byte) []byte {
  buf := make([]byte, saltSize, saltSize+sha1.Size)
  _, err := io.ReadFull(rand.Reader, buf)
  if err != nil {
    fmt.Printf("random read failed: %v", err)
    os.Exit(1)
  }
  hash := sha1.New()
  hash.Write(buf)
  hash.Write(secret)
  return hash.Sum(buf)
}
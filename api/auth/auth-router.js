// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const {
   checkPasswordLength,
   checkUsernameFree,
   checkUsernameExists
}=require('./auth-middleware')
const express = require('express')
const router = express.Router()
const User = require("../users/users-model.js")
const bcrypt = require("bcryptjs")

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
router.post('/reqister',checkUsernameFree,checkPasswordLength,(req,res,next)=>{
   const hash = bcrypt.hashSync(req.body.password,10)
   User.add({username:req.body.username,password:hash})
   .then(newUser=>{
     res.status(201).json(newUser)
   })
   .catch(err =>{
     res.status(500).json({message:err.message})
   })
  
})

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */
router.post('/login',checkUsernameExists,(req,res,next)=>{
  bcrypt.compareSync(req.body.password,req.userData.password)
  .then(verified=>{
    if(verified){
      req.session.user= req.userData
      res.json(`Welcome  ${req.userData.username}`)
    }else{
      res.status(401).json("Invalid credentials")
    }
  })
  .catch(err=>{
    res.status(500).json({message:err.message})
  })
  
})

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
router.get('/logout',(req,res)=>{
  if(req.session){
    req.session.destroy(e=>{
        if(e){
            res.json("Cant log out " + e.message)
        }else{
            res.status(200).json("Logged out")
        }
    })
  }else{
    res.status(200).json("no session")
  }

})

 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router
import { errorHandler } from "./error.js"
import jwt from "jsonwebtoken"

export const verifyToken = (req, res, next) => {
  const token = req.cookies.access_token

  if (!token) {
    return next(errorHandler(401, "Unauthorized"))
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return next(errorHandler(401, "Unauthorized"))
    }
    req.user = user
    next()
  })
}

export const adminOnly = (req, res, next) => {
  //verification of the logged in user
  const token = req.cookies.access_token

  if (!token) {
    return next(errorHandler(401, "Unauthorized"))
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return next(errorHandler(401, "Unauthorized"))
    }

    req.user = user

    // console.log(req.user)

    //
    // ^checking if the logged in user is an admin or not
    if (req.user && req.user.role === "admin") {
      next()
    } else {
      return next(errorHandler(403, "Access Denied, admin only!"))
    }
  })
}
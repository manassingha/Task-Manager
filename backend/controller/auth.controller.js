import User from "../models/user.model.js";
import bcryptjs from "bcryptjs";
import { errorHandler } from "../utils/error.js";
import jwt from "jsonwebtoken";

//signup controller
export const signup = async (req, res, next) => {
  const { name, email, password, profileImageUrl, adminJoinCode } = req.body;

  //   Validating user input
  if (
    !name ||
    !email ||
    !password ||
    name === "" ||
    email === "" ||
    password === ""
  ) {
    return next(errorHandler(400, "All fields are required"));
  }

  //   Checking if user already exists
  const isAlreadyExist = await User.findOne({ email });

  if (isAlreadyExist) {
    return next(errorHandler(400, "User already exists"));
  }

  //   checking user role
  let role = "user";

  if (adminJoinCode && adminJoinCode === process.env.ADMIN_JOIN_CODE) {
    role = "admin";
  }

  // hashing password
  const hashedPassword = bcryptjs.hashSync(password, 10);

  //   creating of new user in the DB
  const newUser = new User({
    name,
    email,
    password: hashedPassword,
    profileImageUrl,
    role,
  });

  //saving the user in DB
  try {
    await newUser.save();
    res.json("Signup successful");
  } catch (error) {
    next(error.message);
  }
};

//signin controller
export const signin = async (req, res, next) => {
  try {
    const { email, password } = req.body;


    //checks if all the inputs are provided
    if (!email || !password || email === "" || password === "") {
      return next(errorHandler(400, "All fields are required"));
    }

    //checks if the user exists in the DB
    const validUser = await User.findOne({ email });

    //if not present
    if (!validUser) {
      return next(errorHandler(404, "User not found!"));
    }

    // compare password
    const validPassword = bcryptjs.compareSync(password, validUser.password);

    if (!validPassword) {
      return next(errorHandler(400, "Wrong Credentials"));
    }

    //jwt token generation
    const token = jwt.sign(
      { id: validUser._id, role: validUser.role },
      process.env.JWT_SECRET,
    );

    //we'll send all the data but not the password
    const { password: pass, ...rest } = validUser._doc;

    res
      .status(200)
      .cookie("access_token", token, { httpOnly: true })
      .json(rest);
  } catch (error) {
    next(error);
  }
};


//get user profile api
export const userProfile = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      return next(errorHandler(404, "User not found!"));
    }

    const { password: pass, ...rest } = user._doc;

    res.status(200).json(rest);
  } catch (error) {
    next(error);
  }
};

//update user profile controller
export const updateUserProfile = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);

    if (!user) {
      return next(errorHandler(404, "User not found!"));
    }

    user.name = req.body.name || user.name;
    user.email = req.body.email || user.email;

    if (req.body.password) {
      user.password = bcryptjs.hashSync(req.body.password, 10);
    }

    const updatedUser = await user.save();

    const { password: pass, ...rest } = user._doc;

    res.status(200).json(rest);
  } catch (error) {
    next(error);
  }
};

//uploading of profile image controller
export const uploadImage = async (req, res, next) => {
  try {
    if (!req.file) {
      return next(errorHandler(400, "No file uploaded"));
    }

    const imageUrl = `${req.protocol}://${req.get("host")}/uploads/${
      req.file.filename
    }`;

    res.status(200).json({ imageUrl });
  } catch (error) {
    next(error);
  }
};


//sign-out or logout controller 
export const signout = async (req, res, next) => {
  try {
    res
      .clearCookie("access_token")
      .status(200)
      .json("User has been loggedout successfully!");
  } catch (error) {
    next(error);
  }
};

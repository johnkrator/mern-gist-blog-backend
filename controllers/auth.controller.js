import bcrypt from "bcryptjs";
import User from "../models/user.model.js";
import errorHandler from "../utils/error.js";
import jwt from "jsonwebtoken";

export const signup = async (req, res, next) => {
    const {username, email, password} = req.body;

    if (!username || !email || !password || username === "" || email === "" || password === "") {
        res.status(400).json({message: "Please fill all the fields"});
    }

    const hashedPassword = bcrypt.hashSync(password, 10);

    const newUser = new User({username, email, password: hashedPassword});

    try {
        await newUser.save();
        res.status(201).json({message: "User created successfully"});
    } catch (error) {
        next(error);
    }
};

export const signin = async (req, res, next) => {
    const {email, password} = req.body;

    try {
        const user = await User.findOne({email});
        if (!user) {
            return next(errorHandler(400, "User not found"));
        }

        const isPasswordValid = bcrypt.compareSync(password, user.password);
        if (!isPasswordValid) {
            return next(errorHandler(400, "Invalid password"));
        }

        const token = jwt.sign(
            {id: user._id, isAdmin: user.isAdmin},
            process.env.JWT_SECRET,
            {expiresIn: "1h"}
        );

        const {password: userPassword, ...userData} = user._doc;

        res
            .status(200)
            .cookie("token", token, {
                httpOnly: true,
            })
            .json(userData);
    } catch (error) {
        next(error);
    }
};
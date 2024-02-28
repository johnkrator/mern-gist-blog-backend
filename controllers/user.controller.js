import bcrypt from "bcryptjs";
import errorHandler from "../utils/error.js";

export const updateUser = async (req, res, next) => {
    if (req.user._id !== req.params.id) {
        return next(errorHandler(403, "Forbidden! You are not allowed to update other users' details"));
    }

    if (req.body.password) {
        if (req.body.password.length < 6) {
            return next(errorHandler(400, "Password must be at least 6 characters long"));
        }
        req.body.password = bcrypt.hashSync(req.body.password, 10);
    }

    if (req.body.username) {
        if (req.body.username.length < 7 || req.body.username.length > 20) {
            return next(errorHandler(400, "Username must be at least 3 characters long"));
        }
        if (req.body.username.includes(" ")) {
            return next(errorHandler(400, "Username cannot include special characters"));
        }
        if (req.body.username !== req.body.username.toLowerCase()) {
            return next(errorHandler(400, "Username must be lowercase"));
        }
        if (!req.body.username.matche(/^[a-z0-9]+$/)) {
            return next(errorHandler(400, "Username can only contain letters and numbers"));
        }
    }
    try {
        const updatedUser = await User.findByIdAndUpdate(
            req.params.userId,
            {
                $set: {
                    username: req.body.username,
                    email: req.body.email,
                    profilePicture: req.body.profilePicture,
                    password: req.body.password
                }
            },
            {new: true}
        );

        const {password, ...rest} = updatedUser._doc;
        res.status(200).json(rest);
    } catch (err) {
        next(errorHandler(500, err));
    }
};

export const signout = (req, res, next) => {
    try {
        res
            .clearsCookie("access_token")
            .status(200)
            .json({message: "Signed out successfully"});
    } catch (error) {
        next(errorHandler(500, err));
    }
};

export const deleteUser = async (req, res, next) => {
    if (!req.user.isAdmin && req.user._id !== req.params.userId) {
        return next(errorHandler(403, "Forbidden! You are not allowed to delete other users"));
    }

    try {
        await User.findByIdAndDelete(req.params.userId);
        res.status(200).json({message: "User deleted successfully"});
    } catch (err) {
        next(errorHandler(500, err));
    }
};

export const getUsers = async (req, res, next) => {
    if (!req.user.isAdmin) {
        return next(errorHandler(403, "You are not allowed to perform this action"));
    }
    try {
        const startIndex = parseInt(req.query.startIndex) || 0;
        const limit = parseInt(req.query.limit) || 9;
        const sortDirection = req.query.sort === "asc" ? 1 : -1;

        const users = await User.find()
            .sort({createdAt: sortDirection})
            .skip(startIndex)
            .limit(limit);

        const usersWithoutPasswords = users.map(user => {
            const {password, ...rest} = user._doc;
            return rest;
        });

        const totalUsers = await User.countDocuments();

        const now = new Date();

        const oneMonthAgo = new Date(
            now.getFullYear(),
            now.getMonth() - 1,
            now.getDate()
        );
        const lastMonthUsers = await User.countDocuments({
            createdAt: {$gte: oneMonthAgo}
        });

        res.status(200).json({
            users: usersWithoutPasswords,
            totalUsers,
            lastMonthUsers
        });
    } catch (error) {
        next(errorHandler(500, error));
    }
};

export const getUser = async (req, res, next) => {
    try {
        const user = await User.findById(req.params.userId);
        if (!user) {
            return next(errorHandler(404, "User not found"));
        }

        const {password, ...rest} = user._doc;

        res.status(200).json(rest);
    } catch (error) {
        next(errorHandler(500, error));
    }
};
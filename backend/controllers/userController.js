import User from "../models/userModel.js";
import asyncHandler from "../middlewares/asyncHandler.js"
import bcrypt from "bcrypt";
import buildToken from "../utils/buildToken.js";

const createUser = asyncHandler(async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !password || !email) {
        throw new Error("please fill the info correctly")

    }
    const userExists = await User.findOne({ email });
    if (userExists) res.status(400).send("the user exists")

    const salt = await bcrypt.genSalt(10)
    const hashedPass = await bcrypt.hash(password, salt);
    const newUser = new User({ username, email, password: hashedPass });

    try {
        await newUser.save()
        buildToken(res, newUser._id);
        res.status(201).json({ _id: newUser._id, username: newUser.username, email: newUser.email, isAdmin: newUser.isAdmin })
    } catch (error) {
        res.status(400)
        throw new Error("invalid user data")
    }

});

const loginUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body
    const userExists = await User.findOne({ email })

    if (userExists) {
        const validPassword = await bcrypt.compare(password, userExists.password)
        if (validPassword) {
            buildToken(res, userExists._id)
            res.status(201).json({
                _id: userExists._id,
                username: userExists.username,
                email: userExists.email,
                isAdmin: userExists.isAdmin
            })
            return;
        }
    }

})

const logoutCurrentUser = asyncHandler(async (req, res) => {
    res.cookie('jwt', '', {
        httpOnly: true,
        expires: new Date(0),
    })
    res.status(200).json({ message: "logout successfully" });

})

const getAllUsers = asyncHandler(async (req, res) => {
    const users = await User.find({})
    res.json(users);
})

const getCurrentUserProfile = asyncHandler(async (req, res) => {
    const user = await User.findByid(req, user._id)
    if (user) {
        res.json({
            _id: user._id,
            username: user.username,
            email: user.email,

        })
    }
    else {
        res.status(404)
        throw new Error("User not found");
    }
})

const updateCurrentUserProfile = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    if (user) {
        user.username = req.body.username || user.username;
        user.email = req.body.email || user.email;

        if (req.body.password) {
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(req.body.password, salt);
            user.password = hashedPassword;
        }
        const updatedUser = await user.save();

        res.json({
            _id: updatedUser._id,
            username: updatedUser.username,
            email: updatedUser.email,
            isAdmin: updatedUser.isAdmin,
        })
    }
    else {
        res.status(404)
        throw new Error("User not found")
    }
});

export { createUser, loginUser, logoutCurrentUser, getAllUsers, getCurrentUserProfile, updateCurrentUserProfile };

import express from "express";
import verifyToken from "../utils/verifyUser.js";
import {deleteUser, getUser, getUsers, signout, updateUser} from "../controllers/user.controller.js";

const router = express.Router();

router.put("/update/:userId", verifyToken, updateUser);
router.get("/getusers", verifyToken, getUsers);
router.get("/getuser/:userId", verifyToken, getUser);
router.get("/deleteuser/:userId", verifyToken, deleteUser);
router.post("/signout", signout);

export default router;
import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import authRoute from "./routes/auth.route.js";
import userRoute from "./routes/user.route.js";

dotenv.config();

const app = express();

app.use(express.json());

mongoose
    .connect(process.env.MONGO_URI)
    .then(() => console.log("Connected to DB"))
    .catch(err => console.log(err));

app.listen(4000, () => {
    console.log("Server started on port 4000");
});

app.use("/api/auth", authRoute);
app.use("/api/user", userRoute);
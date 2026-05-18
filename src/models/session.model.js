import mongoose from "mongoose";
import { refreshToken } from "../controller/auth.controller.js";

const sessionSchema=new mongoose.Schema({
    user:{
        type:mongoose.Schema.Types.ObjectId,
        ref:"users",
        required:[true,"User is required"]
    },
    refreshTokenHash:{
        type:String,
        required:[true,"Refresh token is required"],
    },
    ip:{
        type:String,
        required:[true,"IP Address is required"]
    },
    userAgent:{
        type:String,
        required:[true,"User Agent is required"]
    },
    revoked:{
        type:Boolean,
        default:false
    }
},{
    timestamps:true
})

const sessionModel=mongoose.model("session",sessionSchema)

export default sessionModel;
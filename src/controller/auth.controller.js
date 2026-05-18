import userModel from "../models/user.model.js"
import crypto from 'crypto'
import jwt from 'jsonwebtoken'
import dotenv from 'dotenv'
import  config  from '../config/config.js'
import sessionModel from '../models/session.model.js'   
import { sendEmail } from "../service/email.service.js";
import {generateOtp,getOtpHtml} from "../utils/utils.js";
import otpModel from "../models/otp.model.js"


/***
 * @desc Register a new user
 * @route POST /api/auth/register
 * @access Public
 */
export async function register(req,res) {
    const{username,email,password}=req.body;

    const isAlreadyRegistered=await userModel.findOne({
        $or:[
            {username},{email}
        ]
    })
    
    if(isAlreadyRegistered){
        res.status(409).json({
            message:"Username Already Exists"
        })
    }
    const hashedPassword=crypto.createHash("sha256").update(password).digest("hex");
    
    const user=await userModel.create({
        username,
        email,
        password:hashedPassword
    })

    const otp=generateOtp();
    const html=getOtpHtml(otp);

    const otpHash=crypto.createHash("sha256").update(otp).digest("hex");

    await otpModel.create({ 
        email,
        user:user._id,
        otpHash
    })

    await sendEmail(email,"Verify your email",`Your OTP is ${otp}`,html)
    
    res.status(201).json({
        message:"User registered successfully",
        user:{
            username:user.username,
            email:user.email,
            verified:user.verified
            
        },
        
    })

}

/**
 * @desc Login user
 * @route POST /api/auth/login
 * @access Public
 */
export async function login(req,res){
    const {email,password}=req.body;

    const user=await userModel.findOne({email})
    if(!user){
        return res.status(404).json({
            message:"User not found"
        })
    }
    if(!user.verified){
        return res.status(401).json({
            message:"Please verify your email address"
        })
    } 
    const hashedPassword=crypto.createHash("sha256").update(password).digest("hex");
    const isPasswordValid=hashedPassword===user.password;
    if(!isPasswordValid){
        return res.status(401).json({
            message:"Invalid password"
        })
    }
    
    const refreshToken=jwt.sign({
        id:user._id,            
    },config.JWT_SECRET,{
        expiresIn:"7d"
    })

    const refreshTokenHash=crypto.createHash("sha256").update(refreshToken).digest("hex")

    const session=await sessionModel.create({
        user:user._id,
        refreshTokenHash,
        ip:req.ip,
        userAgent:req.headers["user-agent"]
    })
    const accessToken=jwt.sign({
        id:user._id,
        sessionId:session._id   
    },config.JWT_SECRET,{   
        expiresIn:"15m"
    })
    res.cookie("refreshToken",refreshToken,{
        httpOnly:true,
        secure:true,
        sameSite:"strict",
        maxAge:7*24*60*60*1000 //7days
    })

    res.status(200).json({
        message:"Login successfully",
        user:{
            username:user.username,
            email:user.email,}
        }) 
}



/***
 * @desc Get current user
 * @route GET /api/auth/me
 * @access Private
 */
export async function getMe(req, res) {
}
/***
 * @desc Refresh access token
 * @route POST /api/auth/refresh
 * @access Public
 */
export async function refreshToken(req,res) {
    const refreshToken=req.cookies.refreshToken
    if(!refreshToken){
        return res.status(401).json({
            message:"Unauthorized user!!"
        })
    }
    const decoded=jwt.verify(refreshToken,config.JWT_SECRET);
    
    const refreshTokenHash=crypto.createHash("sha256").update(refreshToken).digest("hex");

    const session=await sessionModel.findOne({
        refreshTokenHash,
        revoked:false,
    })

    if(!session){
        return res.status(401).json({
            message:"Invalid refresh Token"
        })
    }
    
    const accessToken=jwt.sign({
        id:decoded.id
    },config.JWT_SECRET,{
        expiresIn:"15m"
    })

    const newRefreshToken=jwt.sign({
        id:decoded.id,
    },
    config.JWT_SECRET,{
        expiresIn:"7d"
    })
    const newRefreshTokenHash=crypto.createHash("sha256").update(newRefreshToken).digest("hex");

    session.refreshTokenHash=newRefreshTokenHash;
    await session.save();
    res.cookie("refreshToken",newRefreshToken,{
        httpOnly:true,
        secure:true,
        sameSite:"strict",
        maxAge:7*24*60*60*1000 //7days
    })

    res.status(200).json({
        message:"Access token refreshed successfully",
        accessToken
    })

    
    
}

/**
 * @desc Logout user
 * @route POST /api/auth/logout
 * @access Private
 */
export async function logout(req,res) {

    const refreshToken = req.cookies.refreshToken;
    if(!refreshToken){
        return res.status(400).json({
            message:"Refresh token is not found"
        })
    }
    const refreshTokenHash=crypto.createHash("sha256").update(refreshToken).digest("hex");

    const session=await sessionModel.findOne({
        refreshTokenHash,
        revoked:false
    })
    if(!session){
        return res.status(400).json({
            message:"Invalid Refresh Token"
        })
    }
    session.revoked=true;
    await session.save();
    res.clearCookie("refreshToken");

    res.status(200).json({
        message:"Logout successfully"
    })

}

/**
 * @desc Logout user from all devices
 * @route POST /api/auth/logout-all
 * @access Private  
 */
export async function logoutAll(req,res) {
    const refreshToken = req.cookies.refreshToken;
    if(!refreshToken){
        return res.status(400).json({
            message:"Refresh token is not found"
        })
    }

    const decoded=jwt.verify(refreshToken,config.JWT_SECRET);

    await sessionModel.updateMany({
        user:decoded.id,
        revoked:false
    },{
        revoked:true
    })

    res.clearCookie("refreshToken");
    res.status(200).json({
        message:"Logout from all devices successfully"
    })      
}


/**
 * @desc Verify email address
 * @route GET /api/auth/verify-email
 * @access Public
 */
export async function verifyEmail(req, res) {
    const { otp, email } = req.body

    const otpHash = crypto.createHash("sha256").update(otp).digest("hex")

    const otpDoc = await otpModel.findOne({
        email,
        otpHash
    })

    if (!otpDoc) {
        return res.status(400).json({
            message: "Invalid OTP"
        })
    }

    const user = await userModel.findByIdAndUpdate(otpDoc.user, {
        verified: true
    }, {
        new: true
    })

    await otpModel.deleteMany({
        user: otpDoc.user
    })

    return res.status(200).json({
        message: "Email verified successfully",
        user: {
            username: user.username,
            email: user.email,
            verified: user.verified
        }
    })
}
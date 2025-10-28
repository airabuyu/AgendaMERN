import { Request, Response } from "express"; 
import * as Yup from 'yup'
import UserModel from "../models/user.model";
import { encrypt } from "../utils/encryption";
import { generateToken } from "../utils/jwt";
import { IReqUser } from "../middlewares/auth.middleware";

type TRegister = {
    fullName: string
    userName: string
    email: string
    password: string
    confirmPassword: string
}

type TLogin = {
    identifier: string
    password: string
}


const registerValidateSchema = Yup.object({
    fullName: Yup.string().required(),

    userName: Yup.string().required(),

    email: Yup.string().required(),

    password: Yup.string().required(),

    confirmPassword: Yup
        .string()
        .required()
        .oneOf([Yup.ref("password"), ""], "Password is not matched"),

})

export default {

    async register(req: Request, res: Response) {

        const {fullName, userName, email, password, confirmPassword } = req.body as unknown as TRegister;

        try {
        
            await registerValidateSchema.validate({
                fullName,
                userName,
                email,
                password,
                confirmPassword
            })

            const result = await UserModel.create({
                fullName,
                email,
                userName,
                password,
            })

            res.status(200).json({
                message: "Succes Registration",
                data: result
            })


        } catch (error) {
            const err = error as unknown as Error;

            res.status(400).json({
                message: err.message,
                data: null
            })
        }
    },

    async login(req: Request, res: Response) {
        
        
        try {
            const {identifier, password } = req.body as unknown as TLogin;
    
    
            const userByIdentifier = await UserModel.findOne({
    
                $or: [
                    {
                        email: identifier,
                    },
                    {
                        userName: identifier,
                    }
                ]
    
            })
    
    
            if (!userByIdentifier) {
                return res.status(403).json({
                    message: "User is not found",
                    data: null
                })
            }
    
            const validatePassword: boolean = encrypt(password) === userByIdentifier.password
    
            if(!validatePassword) {
                return res.status(403).json({
                    message: "User is not found",
                    data: null
                })
            }

            const token = generateToken({
                id: userByIdentifier._id,
                role: userByIdentifier.role
            })
    
            res.status(200).json({
                message: "Login Success",
                data: token
            })


        } catch (error) {
            const err = error as unknown as Error;

            res.status(400).json({
                message: err.message,
                data: null
            })
        }
    },

    async me(req: IReqUser, res: Response) {
        try {

            const user = req.user;

            const result = await UserModel.findById(user?.id)

            res.status(200).json({
                message: "Success get user profile",
                data: result
            })

        } catch (error) {
            const err = error as unknown as Error;

            res.status(400).json({
                message: err.message,
                data: null
            })
        }
    }

};
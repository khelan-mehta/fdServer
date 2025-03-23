import { Schema, Document } from 'mongoose';

export interface Transaction {
  txnId: string;
  userId: string;
  recieverId: string;
  amount: number;
  userMacAdd: string;
  userLocation: any;
  recieverLocation: any;
  date: Date;
}

export interface User extends Document {
  name: string;
  email: string;
  address: string;
  macAddresses: string[];
  otp: string;
  verifiedOtp: boolean;
  otpExpiresAt: number;
  mobileNumber: string;
  password: string;
  amountAvailable: number;
  isLoggedIn: boolean;
  isKYCVerified: boolean;
  accessToken?: string;
  fraudCount: number;
  transactions: Transaction[];
}

export const UserSchema = new Schema<User>({
  email: { type: String, required: true },
  name: { type: String, required: true },
  address: { type: String, required: true },
  macAddresses: { type: [String], required: true },
  otp: { type: String, required: false },
  otpExpiresAt: { type: Number, required: false },
  verifiedOtp: { type: Boolean, default: false },
  mobileNumber: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  amountAvailable: { type: Number, default: 2000 },
  isLoggedIn: { type: Boolean, default: false },
  isKYCVerified: { type: Boolean, default: false },
  accessToken: { type: String },
  fraudCount: { type: Number, default: 0 },
  transactions: [
    {
      txnId: { type: String, required: false },
      userId: { type: String, required: false },
      recieverId: { type: String, required: false },
      amount: { type: Number, required: false },
      userMacAdd: { type: String, required: false },
      userLocation: { type: Schema.Types.Mixed, required: false},
      recieverLocation: { type: Schema.Types.Mixed, required: false },
      date: { type: Date, default: Date.now },
    },
  ],
});

import { Schema, Document, model } from 'mongoose';

export interface User extends Document {
  email: string;
  password: string;
  gstin?: string;
  fname?: string;
  panNo?: string;
  companyName?: string;
  organizationLocation?: string;
  industryType?: string;
  state?: string;
  cityName?: string;
  zipcode?: string;
  phoneNumber?: string;
  googleId?: string;
  googleToken?: string;
  isGoogleUser?: boolean;
  username?: string;
  otp?: string; // OTP field
  otpExpiresAt?: number; // OTP expiration time in milliseconds
  verifiedOtp?: boolean;
  accessToken?: string;
  isRegistered?: boolean;
}

export const UserSchema = new Schema<User>({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  gstin: { type: String, required: false },
  fname: { type: String, required: false },
  panNo: { type: String, required: false },
  companyName: { type: String, required: false },
  organizationLocation: { type: String, required: false },
  industryType: { type: String, required: false },
  state: { type: String, required: false },
  cityName: { type: String, required: false },
  zipcode: { type: String, required: false },
  username: { type: String, required: false },
  phoneNumber: { type: String, required: false },
  googleId: { type: String, required: false },
  googleToken: { type: String, required: false },
  isGoogleUser: { type: Boolean, default: false },
  otp: { type: String, required: false },
  otpExpiresAt: { type: Number, required: false },
  verifiedOtp: { type: Boolean, default: false },
  accessToken: { type: String, required: false },
  isRegistered: { type: Boolean, default: false },
});

export const UserModel = model<User>('User', UserSchema);

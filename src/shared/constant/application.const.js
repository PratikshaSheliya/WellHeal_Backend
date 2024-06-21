import 'dotenv/config'
export const constants = {
  PORT: process.env.PORT || 3000,
  HOST_URL: process.env.HOST_URL || 'http://localhost:3000',
  API_URL: `${process.env.HOST_URL}/api`,
  ASSET_URL: `${process.env.HOST_URL}/public/`,
  IS_PROD: process.env.NODE_ENV == 'production' ? true : false,
  ADMIN_API_SECRET: "dd165f2d90283b6562b38838c106062a:58f9b24077b836ca3617dd6dc53a26ab759f2d67526065f7b88f895cdf5f8b40f4b5de0b38d89a368d8a763446235a4d86b8fc975d31640ca7f9b67265305167d59083491030535f8cf5e30947098fc6ba148e8dde8c96fb419095c9bdcdd9b8",
  VERIFICATION_TOKEN: process.env.PUBLIC_SECRET_KEY,
  FIREBASE_KEY: process.env.FIREBASE_KEY
};

export const SOCIAL_MEDIA_TYPE = {
  EMAIL: 0,
  GOOGLE: 1,
  FACEBOOK: 2
}

export const STRIPE_CONFIG = {
  webhook_endpoint_secret: process.env.WEBHOOK_ENDPOINT_SECRET,
  cr_USD_INR: process.env.CONVERSION_RATE_USD_TO_INR,
  cr_USD_CENT: process.env.CONVERSION_RATE_USD_TO_CENT,
}

export const REGEX = {
  phone_number: /^(1\s|1|)?((\(\d{3}\))|\d{3})(\-|\s)?(\d{3})(\-|\s)?(\d{4})$/,   //eslint-disable-line
  country_code: /^\+?\d+$/    //eslint-disable-line
}

export const UPLOAD_PATH = {
  Profile: process.env.Aws_Upload_Path,
  Audio: process.env.Aws_Upload_Path_For_Audio,
  Audio_Thumbnail: process.env.Aws_Upload_Path_For_Audio_Images,
  Video: process.env.Aws_Upload_Path_For_Video,
  Video_Thumbnail: process.env.Aws_Upload_Path_For_Video_Images,
  Intro_Video: process.env.Aws_Upload_Path_For_Intro_Video,
  Intro_Video_Thumbnail: process.env.Aws_Upload_Path_For_Intro_Video_Images,
  Quote: process.env.Aws_Upload_Path_For_Quote,
  SubscribeCard: process.env.Aws_Upload_Path_For_SubscribeCard
}
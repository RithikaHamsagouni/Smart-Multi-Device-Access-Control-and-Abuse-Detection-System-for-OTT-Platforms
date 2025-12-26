const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

const sendOTPEmail = async (email, otp) => {
  await transporter.sendMail({
    from: `"OTT Security" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: "OTP Verification - New Device Login",
    text: `Your OTP for new device login is: ${otp}. Valid for 5 minutes.`
  });
};

module.exports = sendOTPEmail;

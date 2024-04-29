const nodemailer = require('nodemailer');
require('dotenv').config();


const transporter = nodemailer.createTransport({
    service: "Gmail",
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
        user: "giogiodagio3@gmail.com",
        pass: "ifpd iniv hsyj zrqj",
    },
});

const sendEmail = async ({
                           to,
                           from,
                           subject,
                           html,
                           attachments,
                           text
                         }) => {
  try {

      const mailOptions = {
          from: from,
          to: to,
          subject: subject,
          html: html,
          attachments: attachments,
          text: text,
      };

      transporter.sendMail(mailOptions);

  } catch (error) {
    console.log(error);
  }
};

exports.sendEmail = async (args) => {
  if (process.env.NODE_ENV !== 'development') {
    return Promise.resolve();
  } else {
    return sendEmail(args);
  }
};
const AudioCall = require("../models/audioCall");
const FriendRequest = require("../models/friendRequest");
const User = require("../models/user");
const VideoCall = require("../models/videoCall");
const catchAsync = require("../utils/catchAsync");
const sanitizeObject = require("../utils/sanitizeObject");

const { generateToken04 } = require("./zegoServerAssistant");

// Please change appID to your appId, appid is a number
// Example: 1234567890
const appID = process.env.ZEGO_APP_ID; // type: number

// Please change serverSecret to your serverSecret, serverSecret is string
// Example：'sdfsdfsd323sdfsdf'
const serverSecret = process.env.ZEGO_SERVER_SECRET; // type: 32 byte length string

exports.getMe = catchAsync(async (req, res, next) => {
  res.status(200).json({
    status: "success",
    data: req.user,
  });
});

exports.updateMe = catchAsync(async (req, res, next) => {
  const sanitizedObject = sanitizeObject(
    req.body,
    "firstName",
    "lastName",
    "about",
    "avatar"
  );

  const userDoc = await User.findByIdAndUpdate(req.user._id, sanitizedObject);

  res.status(200).json({
    status: "success",
    data: userDoc,
    message: "User Updated successfully",
  });
});

exports.getUsers = catchAsync(async (req, res, next) => {
  const allUsers = await User.find({
    verified: true,
  }).select("firstName lastName _id");

  const thisUser = req.user;

  const remainingUsers = allUsers.filter(
    (user) =>
      !thisUser.friends.includes(user._id) &&
      user._id.toString() !== req.user._id.toString()
  );

  res.status(200).json({
    status: "success",
    data: remainingUsers,
    message: "Users found successfully!",
  });
});

exports.getAllVerifiedUsers = catchAsync(async (req, res, next) => {
  const allUsers = await User.find({
    verified: true,
  }).select("firstName lastName _id");

  const remainingUsers = allUsers.filter(
    (user) => user._id.toString() !== req.user._id.toString()
  );

  res.status(200).json({
    status: "success",
    data: remainingUsers,
    message: "Users found successfully!",
  });
});

exports.getAllFriendRequests = catchAsync(async (req, res, next) => {
  const friendRequests = await FriendRequest.find({ recipient: req.user._id })
    .populate("sender")
    .select("_id firstName lastName");

  res.status(200).json({
    status: "success",
    data: friendRequests,
    message: "Requests found successfully!",
  });
});

exports.getFriends = catchAsync(async (req, res, next) => {
  const thisUser = await User.findById(req.user._id).populate(
    "friends",
    "_id firstName lastName"
  );
  res.status(200).json({
    status: "success",
    data: thisUser.friends,
    message: "Friends found successfully!",
  });
});

/**
 * Authorization authentication token generation
 */

exports.generateZegoToken = catchAsync(async (req, res, next) => {
  try {
    const { userId, roomId } = req.body;

    const effectiveTimeInSeconds = 3600; //type: number; unit: s; token expiration time, unit: second
    const payloadObject = {
      roomId, // Please modify to the user's roomID
      // The token generated allows loginRoom (login room) action
      // The token generated in this example allows publishStream (push stream) action
      privilege: {
        1: 1, // loginRoom: 1 pass , 0 not pass
        2: 1, // publishStream: 1 pass , 0 not pass
      },
      streamIdList: null,
    }; //
    const payload = JSON.stringify(payloadObject);
    // Build token
    const token = generateToken04(
      appID * 1, // APP ID NEEDS TO BE A NUMBER
      userId,
      serverSecret,
      effectiveTimeInSeconds,
      payload
    );
    res.status(200).json({
      status: "success",
      message: "Token generated successfully",
      token,
    });
  } catch (err) {
    console.log(err);
  }
});

exports.startAudioCall = catchAsync(async (req, res, next) => {
  const from = req.user._id;
  const to = req.body.id;

  const fromUser = await User.findById(from);
  const toUser = await User.findById(to);

  // create a new call audioCall Doc and send required data to client
  const newAudioCall = await AudioCall.create({
    participants: [from, to],
    from,
    to,
    status: "Ongoing",
  });

  res.status(200).json({
    data: {
      from: toUser,
      roomID: newAudioCall._id,
      streamID: to,
      userID: from,
      userName: from,
    },
  });
});

exports.startVideoCall = catchAsync(async (req, res, next) => {
  const from = req.user._id;
  const to = req.body.id;

  const fromUser = await User.findById(from);
  const toUser = await User.findById(to);

  // create a new call videoCall Doc and send required data to client
  const newVideoCll = await VideoCall.create({
    participants: [from, to],
    from,
    to,
    status: "Ongoing",
  });

  res.status(200).json({
    data: {
      from: toUser,
      roomID: newVideoCll._id,
      streamID: to,
      userID: from,
      userName: from,
    },
  });
});

exports.getCallLogs = catchAsync(async (req, res, next) => {
  const userId = req.user._id;

  const callLogs = [];

  const audioCalls = await AudioCall.find({
    participants: { $all: [userId] },
  }).populate("from to");

  const videoCalls = await VideoCall.find({
    participants: { $all: [userId] },
  }).populate("from to");

  for (let elm of audioCalls) {
    const missed = elm.verdict !== "Accepted";
    if (elm.from._id.toString() === userId.toString()) {
      const otherUser = elm.to;

      // outgoing
      callLogs.push({
        id: elm._id,
        img: otherUser.avatar,
        name: otherUser.firstName,
        online: true,
        incoming: false,
        missed,
      });
    } else {
      // incoming
      const otherUser = elm.from;

      // outgoing
      callLogs.push({
        id: elm._id,
        img: otherUser.avatar,
        name: otherUser.firstName,
        online: true,
        incoming: false,
        missed,
      });
    }
  }

  for (let element of videoCalls) {
    const missed = element.verdict !== "Accepted";
    if (element.from._id.toString() === userId.toString()) {
      const otherUser = element.to;

      // outgoing
      callLogs.push({
        id: element._id,
        img: otherUser.avatar,
        name: otherUser.firstName,
        online: true,
        incoming: false,
        missed,
      });
    } else {
      // incoming
      const otherUser = element.from;

      // outgoing
      callLogs.push({
        id: element._id,
        img: otherUser.avatar,
        name: otherUser.firstName,
        online: true,
        incoming: false,
        missed,
      });
    }
  }

  res.status(200).json({
    status: "success",
    message: "Call Logs Found successfully!",
    data: callLogs,
  });
});

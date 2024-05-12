const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
dotenv.config({ path: "./config.env" });
const app = require("./app");
const http = require("http");
const server = http.createServer(app);
const { Server } = require("socket.io");
const { promisify } = require("util");
const User = require("./models/user");
const FriendRequest = require("./models/friendRequest");
const Conversation = require("./models/conversation");
const AudioCall = require("./models/audioCall");
const VideoCall = require("./models/videoCall");


// In case of uncaught exceptions
process.on("uncaughtException", (err) => {
  console.log(err);
  console.log("UNCAUGHT Exception! Shutting down ...");
  process.exit(1); // Exit program
});


// Create an io server and allow for CORS from http://localhost:3001 with GET and POST methods
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
});

// Replace <PASSWORD> with actual password from env file
const DB = process.env.DATABASE.replace(
  "<PASSWORD>",
  process.env.DATABASE_PASSWORD
);

mongoose
    .connect(DB, {
      // useNewUrlParser: true,  // Parse MongoDB connection strings using new parser
      // useCreateIndex: true,    // Automatically create indexes for any schema indexes defined in the schema
      // useFindAndModify: false, // Use MongoDB's findOneAndUpdate() and findOneAndDelete() instead of findAndModify()
      // useUnifiedTopology: true, // Use new Server Discovery and Monitoring engine
    })
    .then((con) => {
      console.log("Connected to database...");
    });

const port = process.env.PORT || 8000; // Port default 3001 or otherwise 8000

// Server listens port 3001
server.listen(port, () => {
  console.log(`Server is listening port ${port} ...`);
});

// Listen for when the client connects via socket.io-client
io.on("connection", async (socket) => {

  const userId = socket.handshake.query["userId"];
  if (userId != null && Boolean(userId)) {
    try {
      const updated = await User.findByIdAndUpdate(userId, {
        socketId: socket.id,
        status: "Online",
      });

    } catch (e) {
      console.log(e);
    }
  }

  // Socket event listeners...
  socket.on("friendRequest", async (data) => {

    // Find the recipient's socketId by querying the User model with the 'to' value from the received data
    const to = await User.findById(data.to).select("socketId");
    // Find the sender's socketId by querying the User model with the 'from' value from the received data
    const from = await User.findById(data.from).select("socketId");

    // Check if a friend request already exists between the sender and recipient (in either direction)
    if (await FriendRequest.findOne({
      $or: [
        { sender: data.from, recipient: data.to },
        { sender: data.to, recipient: data.from }
      ]
    }))
    {
      return;
    }

    // If no friend request exists, create a new friend request document in the database
    await FriendRequest.create({
      sender: data.from,
      recipient: data.to,
    });

    // Emit a 'newFriendRequest' event to the recipient's socket
    // This event will notify the recipient that a new friend request has been received
    io.to(to?.socketId).emit("newFriendRequest", {
      message: "New friend request received",
    });

    // Emit a 'friendRequestSent' event to the sender's socket
    // This event will notify the sender that their friend request has been sent successfully
    io.to(from?.socketId).emit("friendRequestSent", {
      message: "Request Sent successfully!",
    });
  });

  socket.on("acceptFriendRequest", async (data) => {
    // accept friend request => add ref of each other in friends array
    const reqDoc = await FriendRequest.findById(data.requestId);

    const sender = await User.findById(reqDoc.sender);
    const receiver = await User.findById(reqDoc.recipient);


    sender.friends.push(reqDoc.recipient);
    receiver.friends.push(reqDoc.sender);

    await receiver.save({ new: true, validateModifiedOnly: true });
    await sender.save({ new: true, validateModifiedOnly: true });

    await FriendRequest.findByIdAndDelete(data.requestId);

    // delete this request doc
    // emit event to both of them

    // emit event request accepted to both
    io.to(sender?.socketId).emit("friendRequestAccepted", {
      message: "Friend Request Accepted",
    });
    io.to(receiver?.socketId).emit("friendRequestAccepted", {
      message: "Friend Request Accepted",
    });
  });

  socket.on("getIndividualConversation", async ({ userId }, callback) => {
    const existingConversations = await Conversation.find({
      participants: { $all: [userId] },
    }).populate("participants", "firstName lastName avatar _id email status");

    // db.books.find({ authors: { $elemMatch: { name: "John Smith" } } })

    console.log(existingConversations);
    callback(existingConversations);
  });

  socket.on("startConversation", async (data) => {
    // data: {to: from:}

    const { to, from } = data;

    // check if there is any existing conversation

    const existingConversations = await Conversation.find({
      participants: { $size: 2, $all: [to, from] },
    }).populate("participants", "firstName lastName _id email status");

    // if no => create a new oneToOneMessage doc & emit event "startChat" & send conversation details as payload
    if (existingConversations.length === 0) {
      let newChat = await Conversation.create({
        participants: [to, from],
      });

      newChat = await Conversation.findById(newChat).populate(
        "participants",
        "firstName lastName _id email status"
      );

      socket.emit("startChat", newChat);
    }
    // if yes => just emit event "startChat" & send conversation details as payload
    else {
      socket.emit("startChat", existingConversations[0]);
    }
  });

  socket.on("getMessages", async (data, callback) => {
    try {
      const { messages } = await Conversation.findById(
        data.conversationId
      ).select("messages");
      callback(messages);
    } catch (error) {
      console.log(error);
    }
  });

  // Handle incoming text/link messages
  socket.on("textMessage", async (data) => {

    // data: {to, from, text}

    const { message, conversationId, from, to, type } = data;

    const toUser = await User.findById(to);
    const fromUser = await User.findById(from);

    // message => {to, from, type, createdAt, text, file}

    const newMessage = {
      to: to,
      from: from,
      type: type,
      createdAt: Date.now(),
      text: message,
    };

    // fetch oneToOneMessage Doc & push a new message to existing conversation
    const chat = await Conversation.findById(conversationId);
    chat.messages.push(newMessage);
    // save to db`
    await chat.save({ new: true, validateModifiedOnly: true });

    // emit incoming_message -> to user

    io.to(toUser?.socketId).emit("newMessage", {
      conversationId,
      message: newMessage,
    });

    // emit outgoing_message -> from user
    io.to(fromUser?.socketId).emit("newMessage", {
      conversationId,
      message: newMessage,
    });
  });

  // handle Media/Document Message
  socket.on("fileMessage", (data) => {

    // data: {to, from, text, file}

    // Get the file extension
    const fileExtension = path.extname(data.file.name);

    // Generate a unique filename
    const filename = `${Date.now()}_${Math.floor(
      Math.random() * 10000
    )}${fileExtension}`;

    // upload file to AWS s3

    // create a new conversation if its dosent exists yet or add a new message to existing conversation

    // save to db

    // emit incoming_message -> to user

    // emit outgoing_message -> from user
  });

  // -------------- HANDLE AUDIO CALL SOCKET EVENTS ----------------- //

  // handle startAudioCall event
  socket.on("startAudioCall", async (data) => {
    const { from, to, roomID } = data;

    const toUser = await User.findById(to);
    const fromUser = await User.findById(from);


    // send notification to receiver of call
    io.to(toUser?.socketId).emit("audioCallNotification", {
      from: fromUser,
      roomID,
      streamID: from,
      userID: to,
      userName: to,
    });
  });

  // handle audioCallNotPicked
  socket.on("audioCallNotPicked", async (data) => {
    // find and update call record
    const { to, from } = data;

    const toUser = await User.findById(to);

    await AudioCall.findOneAndUpdate(
      {
        participants: { $size: 2, $all: [to, from] },
      },
      { verdict: "Missed", status: "Ended", endedAt: Date.now() }
    );

    // TODO => emit call_missed to receiver of call
    io.to(toUser?.socketId).emit("audioCallMissed", {
      from,
      to,
    });
  });

  // handle audioCallAccepted
  socket.on("audioCallAccepted", async (data) => {
    const { to, from } = data;

    const fromUser = await User.findById(from);

    // find and update call record
    await AudioCall.findOneAndUpdate(
      {
        participants: { $size: 2, $all: [to, from] },
      },
      { verdict: "Accepted" }
    );

    // TODO => emit call_accepted to sender of call
    io.to(fromUser?.socketId).emit("audioCallAccepted", {
      from,
      to,
    });
  });

  // handle audioCallDenied
  socket.on("audioCallDenied", async (data) => {
    // find and update call record
    const { to, from } = data;

    await AudioCall.findOneAndUpdate(
      {
        participants: { $size: 2, $all: [to, from] },
      },
      { verdict: "Denied", status: "Ended", endedAt: Date.now() }
    );

    const fromUser = await User.findById(from);
    // TODO => emit call_denied to sender of call

    io.to(fromUser?.socketId).emit("audioCallDenied", {
      from,
      to,
    });
  });

  // handle userIsBusyAudioCall
  socket.on("userIsBusyAudioCall", async (data) => {
    const { to, from } = data;
    // find and update call record
    await AudioCall.findOneAndUpdate(
      {
        participants: { $size: 2, $all: [to, from] },
      },
      { verdict: "Busy", status: "Ended", endedAt: Date.now() }
    );

    const fromUser = await User.findById(from);
    // TODO => emit onAnotherAudioCall to sender of call
    io.to(fromUser?.socketId).emit("onAnotherAudioCall", {
      from,
      to,
    });
  });

  // --------------------- HANDLE VIDEO CALL SOCKET EVENTS ---------------------- //

  // handle startVideoCall event
  socket.on("startVideoCall", async (data) => {
    const { from, to, roomID } = data;


    const toUser = await User.findById(to);
    const fromUser = await User.findById(from);

    // send notification to receiver of call
    io.to(toUser?.socketId).emit("videoCallNotification", {
      from: fromUser,
      roomID,
      streamID: from,
      userID: to,
      userName: to,
    });
  });

  // handle videoCallNotPicked
  socket.on("videoCallNotPicked", async (data) => {
    // find and update call record
    const { to, from } = data;

    const toUser = await User.findById(to);

    await VideoCall.findOneAndUpdate(
      {
        participants: { $size: 2, $all: [to, from] },
      },
      { verdict: "Missed", status: "Ended", endedAt: Date.now() }
    );

    // TODO => emit call_missed to receiver of call
    io.to(toUser?.socketId).emit("videoCallMissed", {
      from,
      to,
    });
  });

  // handle videoCallAccepted
  socket.on("videoCallAccepted", async (data) => {
    const { to, from } = data;

    const fromUser = await User.findById(from);

    // find and update call record
    await VideoCall.findOneAndUpdate(
      {
        participants: { $size: 2, $all: [to, from] },
      },
      { verdict: "Accepted" }
    );

    // TODO => emit call_accepted to sender of call
    io.to(fromUser?.socketId).emit("videoCallAccepted", {
      from,
      to,
    });
  });

  // handle videoCallDenied
  socket.on("videoCallDenied", async (data) => {
    // find and update call record
    const { to, from } = data;

    await VideoCall.findOneAndUpdate(
      {
        participants: { $size: 2, $all: [to, from] },
      },
      { verdict: "Denied", status: "Ended", endedAt: Date.now() }
    );

    const fromUser = await User.findById(from);
    // TODO => emit call_denied to sender of call

    io.to(fromUser?.socketId).emit("videoCallDenied", {
      from,
      to,
    });
  });

  // handle userIsBusyVideoCall
  socket.on("userIsBusyVideoCall", async (data) => {
    const { to, from } = data;
    // find and update call record
    await VideoCall.findOneAndUpdate(
      {
        participants: { $size: 2, $all: [to, from] },
      },
      { verdict: "Busy", status: "Ended", endedAt: Date.now() }
    );

    const fromUser = await User.findById(from);
    // TODO => emit onAnotherVideoCall to sender of call
    io.to(fromUser?.socketId).emit("onAnotherVideoCall", {
      from,
      to,
    });
  });

  // -------------- HANDLE SOCKET DISCONNECTION ----------------- //


  socket.on("end", async (data) => {
    // Find user by ID and set status as offline

    if (data.userId) {
      await User.findByIdAndUpdate(data.userId, { status: "Offline" });
    }

    // broadcast to all conversation rooms of this user that this user is offline (disconnected)

    console.log("closing connection");
    socket.disconnect(0);
  });
});

process.on("unhandledRejection", (err) => {
  console.log(err);
  console.log("UNHANDLED REJECTION! Shutting down ...");
  server.close(() => {
    process.exit(1); //  Exit Code 1 indicates that a container shut down, either because of an application failure.
  });
});

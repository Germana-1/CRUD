import express from "express";
import { v4 as uuidv4 } from "uuid";
import users from "./database.js";
import { hash, compare } from "bcryptjs";
import jwt from "jsonwebtoken";
import "dotenv/config";

const app = express();

app.use(express.json());

//MIDDLEWARES
const userArealdyExistsMiddleware = (req, res, next) => {
  const userArealdyExists = users.find((el) => el.email === req.body.email);

  if (userArealdyExists) {
    return res.status(409).json({ message: "E-mail already registered" });
  }
  return next();
};

const ensureAuthMiddleware = (req, res, next) => {
  let authorization = req.headers.authorization;

  if (!authorization) {
    return res.status(401).json({
      message: "Missing authorization headers",
    });
  }

  authorization = authorization.split(" ")[1];

  return jwt.verify(authorization, process.env.SECRET_KEY, (error, decoded) => {
    if (error) {
      return res.status(401).json({
        message: "Missing authorization headers",
      });
    }
    req.user = { id: decoded.sub, isAdm: decoded.isAdm };
    return next();
  });
};

const isAdmMiddleware = (req, res, next) => {
  const user = users.find((el) => el.uuid === req.user.id);

  if (!user.isAdm) {
    return res.status(403).json({
      message: "missing admin permissions",
    });
  }
  return next();
};

// const ensureUserExistsMiddleware = (req, res, next) => {
//   const userIndex = users.findIndex((el) => el.uuid === req.params.id);

//   if (userIndex === -1) {
//     res.status(404).json({ message: "User not found" });
//   }
//   return next();
// };

const haveAdmPermissionMiddleware = (req, res, next) => {
  if (!req.user.isAdm && req.params.id !== req.user.id) {
    return res.status(403).json({ message: "missing admin permissions" });
  }
  return next();
};

//SERVECES
const createUserServece = async ({ email, name, isAdm, password }) => {
  const userData = {
    email: email,
    name: name,
    isAdm: isAdm,
    uuid: uuidv4(),
    createdOn: new Date(),
    updatedOn: new Date(),
  };

  const newUser = { ...userData, password: await hash(password, 10) };
  users.push(newUser);
  return [201, userData];
};

const createSessionServece = async ({ email, password }) => {
  const user = users.find((el) => el.email === email);
  if (!user) {
    return [401, { message: "Wrong email/password" }];
  }

  const passwordMatch = await compare(password, user.password);
  if (!passwordMatch) {
    return [401, { message: "Wrong email/password" }];
  }

  const token = jwt.sign({ isAdm: user.isAdm }, process.env.SECRET_KEY, {
    expiresIn: "24h",
    subject: user.uuid,
  });
  return [200, { token }];
};

const userProfileServece = (req) => {
  const user = users.find((el) => el.uuid === req.user.id);
  delete user.password;
  return [200, user];
};

const updatedUserServece = async (req) => {
  const user = users.find((el) => el.uuid === req.params.id);
  if (!user) {
    return [404, { message: "User not found" }];
  }

  let data = { ...req.body, updatedOn: new Date() };
  if (req.body.password) {
    data = {
      ...data,
      password: await hash(req.body.password, 10),
    };
  }
  console.log(user);

  if (req.body.isAdm !== undefined && user) {
    data.isAdm = user.isAdm;
  }

  const userUpdated = Object.assign(user, data);
  const userData = { ...userUpdated };
  delete userData.password;

  return [200, userData];
};

const deleteUserServece = (req) => {
  const userIndex = users.findIndex((el) => el.uuid === req.params.id);

  if (userIndex === -1) {
    return [404, { message: "User not found" }];
  }

  users.splice(userIndex, 1);

  return [204, {}];
};

//CONTROLLERS
const createUserController = async (req, res) => {
  const [status, data] = await createUserServece(req.body);
  return res.status(status).json(data);
};

const listUsersController = (req, res) => {
  return res.json(users);
};

const createSessionController = async (req, res) => {
  const [status, data] = await createSessionServece(req.body);
  return res.status(status).json(data);
};

const userProfileController = (req, res) => {
  const [status, data] = userProfileServece(req);
  return res.status(status).json(data);
};

const updatedUserController = async (req, res) => {
  const [status, data] = await updatedUserServece(req);
  return res.status(status).json(data);
};

const deleteUserController = (req, res) => {
  const [status, data] = deleteUserServece(req);
  return res.status(status).json(data);
};

//ROUTERS
app.post("/users", userArealdyExistsMiddleware, createUserController);
app.get("/users", ensureAuthMiddleware, isAdmMiddleware, listUsersController);
app.post("/login", createSessionController);
app.get("/users/profile", ensureAuthMiddleware, userProfileController);
app.patch(
  "/users/:id",
  ensureAuthMiddleware,
  haveAdmPermissionMiddleware,
  updatedUserController
);
app.delete(
  "/users/:id",
  ensureAuthMiddleware,
  haveAdmPermissionMiddleware,
  deleteUserController
);

app.listen(3000);

export default app;

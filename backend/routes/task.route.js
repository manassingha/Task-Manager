import express from "express"
import { adminOnly, verifyToken } from "../utils/verifyUser.js"
import {
  createTask,
  deleteTask,
  getDashboardData,
  getTaskById,
  getTasks,
  updateTask,
  updateTaskChecklist,
  updateTaskStatus,
  userDashboardData,
} from "../controller/task.controller.js"

const router = express.Router()

//admin only routes
router.post("/create", verifyToken, adminOnly, createTask)
router.delete("/:id", verifyToken, adminOnly, deleteTask)
router.get("/dashboard-data", verifyToken, adminOnly, getDashboardData)

//user tasks routes
router.get("/", verifyToken, getTasks)
router.get("/user-dashboard-data", verifyToken, userDashboardData)
router.get("/:id", verifyToken, getTaskById)
router.put("/:id", verifyToken, updateTask)
router.put("/:id/status", verifyToken, updateTaskStatus)
router.put("/:id/todo", verifyToken, updateTaskChecklist)

export default router
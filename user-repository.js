import DBLocal from 'db-local'

import crypto from 'crypto'
import bcrypt from 'bcrypt'

import { SALT_ROUNDS } from './config.js'

const { Schema } = new DBLocal({ path: './db' })

const User = Schema('User', {
  _id: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true }
})

export class UserRepository {
  static async create ({ username, password }) {
    // Validar con ZOD
    Validation.username(username)
    Validation.password(password)

    // Asegurarse que el username no existe, la database deberia tener unique el username
    const user = User.findOne({ username })
    if (user) throw new Error('username already exists')

    const id = crypto.randomUUID()// Ojala lo genera la database
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS) // -< hashsync bloquea el thread principal

    User.create({
      _id: id,
      username,
      password: hashedPassword
    }).save()
    return id
  }

  static async login ({ username, password }) {
    Validation.username(username)
    Validation.password(password)

    const user = User.findOne({ username })
    if (!user) throw new Error('username does not exist')

    const isValid = await bcrypt.compare(password, user.password)
    if (!isValid) throw new Error('password invalid')

    const { password: _, ...publicUser } = user // -> para no devolver el password, o crear objeto nuevo solo con lo que SI
    return publicUser
  }
}

class Validation {
  static username (username) {
    if (typeof username !== 'string') throw new Error('username must be a string')
    if (username.length < 3) throw new Error('username must be at least 3 characters long')
  }

  static password (password) {
    if (typeof password !== 'string') throw new Error('password must be a string')
    if (password.length < 6) throw new Error('passwordm ust be a tleast 6 characters long')
  }
}

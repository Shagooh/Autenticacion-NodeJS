import express from 'express'
import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser'
import { PORT, SECRET_JWT_KEY } from './config.js'
import { UserRepository } from './user-repository.js'

const app = express()

app.set('view engine', 'ejs')

app.use(express.json())
app.use(cookieParser())

app.use((req, res, next) => {
  const token = req.cookies.access_token
  req.session = { user: null }

  try {
    const data = jwt.verify(token, SECRET_JWT_KEY)
    req.session.user = data
  } catch {}
  next()
})

app.get('/', (req, res) => {
  const { user } = req.session
  res.render('index', user)
})

app.post('/login', async (req, res) => {
  const { username, password } = req.body
  try {
    const user = await UserRepository.login({ username, password })
    const token = jwt.sign({ id: user._id, username: user.username },
      SECRET_JWT_KEY,
      {
        expiresIn: '1h'
      })

    const refreshToken = jwt.sign({ id: user._id, username: user.username },
      SECRET_JWT_KEY,
      {
        expiresIn: '7d'
      })

    res
      .cookie('access_token', token, {
        httpOnly: true, // la cookie sol ose puede acceder en el servidor
        secure: process.env.NODE_ENV === 'production', // solo con https
        sameSite: 'strict', // solo accesible en el mismo dominio
        maxAge: 1000 * 60 * 60 // cookie valida por 1 hora
      })
      .send({ user })
  } catch (error) {
    res.status(401).send(error.message)
  }
})

app.post('/register', async (req, res) => {
  const { username, password } = req.body
  console.log(req.body)
  try {
    const id = await UserRepository.create({ username, password })

    res.send({ id })
  } catch (error) {
    // no es buena idea mandar log error del repository
    res.status(400).send(error.message)
  }
})

app.post('/logout', (req, res) => {
  res
    .clearCookie('access_token')
    .json({ message: 'Logout succesful' })
    // Por ejemplo Se puede direccionar al home
})

// sesion del usuario podria ser con express-sesion o utilizar redis como basedatos para sesion
// utilizaremos JWT
app.get('/protected', (req, res) => {
  const { user } = req.session
  if (!user) return res.status(403).send('Access not authorized')
  res.render('protected', user) // -> data contiene { _id, username }
})

app.listen(PORT, () => {
  console.log(`Server running on PORT:${PORT}`)
})

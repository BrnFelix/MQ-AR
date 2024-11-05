const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());

// Conexão com o MongoDB
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/monitoramento_qualidade_ar';
mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log('Conectado ao MongoDB! Servidor rodando na porta ' + PORT);
  })
  .catch((err) => {
    console.error('Erro ao conectar ao MongoDB:', err);
  });

app.use(express.json());

// ==================
// Definição dos Esquemas e Modelos
// ==================

// Esquema de Usuários
const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  password: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);

// Esquema de Dispositivos
const deviceSchema = new mongoose.Schema({
  deviceId: { type: String, unique: true, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, required: true },
  deviceName: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const Device = mongoose.model('Device', deviceSchema);

// Esquema de Leituras
const readingSchema = new mongoose.Schema({
  deviceId: { type: mongoose.Schema.Types.ObjectId, required: true },
  timestamp: { type: Date, default: Date.now },
  temperature: { type: Number, required: true },
  humidity: { type: Number, required: true },
  gasLevel: { type: Number, required: true },
  createdAt: { type: Date, default: Date.now },
});

const Reading = mongoose.model('Reading', readingSchema);

// Configuração de chaves secretas e duração dos tokens
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET || 'access_secret_key';
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || 'refresh_secret_key';
const ACCESS_TOKEN_EXPIRATION = '15m';
const REFRESH_TOKEN_EXPIRATION = '7d';

function generateAccessToken(payload) {
  return jwt.sign(payload, ACCESS_TOKEN_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRATION });
}

function generateRefreshToken(payload) {
  return jwt.sign(payload, REFRESH_TOKEN_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRATION });
}

// Middleware para verificar o token JWT
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user; // Salva o usuário decifrado no request
    next();
  });
};

// Middleware para verificar o refresh token
const authenticateRefreshToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// ==================
// Rotas de Usuários
// ==================

// Registro de usuário
app.post('/api/register', async (req, res) => {
  const { username, password, email } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Usuário já existe' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      username,
      password: hashedPassword,
      email,
      createdAt: new Date(),
      updatedAt: new Date()
    });

    const savedUser = await newUser.save();
    res.status(201).send({
      _id: savedUser._id,
      username: savedUser.username,
      email: savedUser.email,
      createdAt: savedUser.createdAt,
      updatedAt: savedUser.updatedAt,
      message: "Usuário registrado com sucesso!"
    });
  } catch (err) {
    res.status(500).send({ error: "Erro ao registrar usuário" });
  }
});

// Endpoint de login do usuário
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({ error: 'Usuário não encontrado' });
    }

    if (!(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Senha inválida' });
    }

    const payload = { userId: user._id, email: user.email, username: user.username };
    const accessToken = generateAccessToken(payload);
    const refreshToken = generateRefreshToken(payload);

    res.json({
      message: 'Login realizado com sucesso',
      accessToken,
      refreshToken
    });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao realizar login' });
  }
});

// Endpoint de Refresh Token
app.post('/api/refresh', authenticateRefreshToken, async (req, res) => {
  try {
    const { userId } = req.user;
    const user = await User.findOne({ _id: userId });

    if (!user) {
      return res.status(403).json({ error: 'Usuário não encontrado' });
    }

    const { email, username } = user;
    const newAccessToken = generateAccessToken({ userId, email, username });

    res.json({ accessToken: newAccessToken });
  } catch (err) {
    res.status(403).json({ error: 'Refresh token inválido' });
  }
});

// Obter informações do usuário
app.get('/api/users/', authenticateToken, async (req, res) => {
  try {
    const id = req.user.userId;
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }
    res.status(200).json(user);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao buscar usuário' });
  }
});

// Atualizar usuário
app.put('/api/users/', authenticateToken, async (req, res) => {
  try {
    const id = req.user.userId;
    const { username, email, currentPassword, newPassword } = req.body;

    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    // Verifica se a senha atual foi fornecida e se a nova senha é válida
    if (currentPassword && newPassword) {
      const isMatch = await bcrypt.compare(currentPassword, user.password);
      if (!isMatch) {
        return res.status(401).json({ error: 'Senha atual inválida' });
      }

      const hashedNewPassword = await bcrypt.hash(newPassword, 10);
      user.password = hashedNewPassword;
    }

    if (email) {
      const existingUser = await User.findOne({ email });
      if (existingUser && existingUser._id != id) {
        return res.status(400).json({ error: 'Email já cadastrado' });
      }
      user.email = email;
    }

    // Atualiza outros dados do usuário, se houver
    user.username = username || user.username;
    user.updatedAt = new Date();

    const updatedUser = await user.save();
    res.status(200).json(updatedUser);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao atualizar usuário' });
  }
});

// Deletar usuário
app.delete('/api/users/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const deletedUser = await User.findByIdAndDelete(id);
    if (!deletedUser) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }
    res.status(200).json({ message: 'Usuário deletado com sucesso' });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao deletar usuário' });
  }
});

// ==================
// Rotas de Dispositivos
// ==================

// Registro de dispositivo
app.post('/api/devices', authenticateToken, async (req, res) => {
  const userId = req.user.userId;

  try {
    const { deviceId, deviceName } = req.body;

    // Verifica se o dispositivo já existe
    const existingDevice = await Device.findOne({ deviceId });
    if (existingDevice) {
      return res.status(400).json({ error: 'Dispositivo já cadastrado' });
    }

    const newDevice = new Device({
      deviceId,
      userId,
      deviceName,
      createdAt: new Date(),
      updatedAt: new Date()
    });

    await newDevice.save();
    res.status(201).json({ message: 'Dispositivo registrado com sucesso', deviceId });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao registrar dispositivo' });
  }
});

// Obter dispositivos do usuário
app.get('/api/devices', authenticateToken, async (req, res) => {
  const userId = req.user.userId;

  try {
    const devices = await Device.find({ userId });
    res.status(200).json(devices);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao buscar dispositivos' });
  }
});

// ==================
// Rotas de Leituras
// ==================

// Registro de leituras
app.post('/api/readings', authenticateToken, async (req, res) => {
  const { deviceId, temperature, humidity, gasLevel } = req.body;

  try {
    const newReading = new Reading({
      deviceId,
      temperature,
      humidity,
      gasLevel,
      createdAt: new Date()
    });

    await newReading.save();
    res.status(201).json({ message: 'Leitura registrada com sucesso' });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao registrar leitura' });
  }
});

// Obter leituras de um dispositivo específico
app.get('/api/readings/:deviceId', authenticateToken, async (req, res) => {
  const { deviceId } = req.params;

  try {
    const readings = await Reading.find({ deviceId }).sort({ createdAt: -1 });
    res.status(200).json(readings);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao buscar leituras' });
  }
});

// Inicia o servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});

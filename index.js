
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Conexão com o MongoDB
const MONGODB_URI = String(process.env.MONGODB_URI);
mongoose.connect(MONGODB_URI).then(() => {
  console.log('Conectado ao MongoDB! Servidor rodando na porta ' + PORT);
}).catch((err) => {
  console.error('Erro ao conectar ao MongoDB:', err);
});

const corsOptions = {
  origin: process.env.CORS_ORIGIN || 'http://localhost:3001',
  methods: ['GET', 'POST', 'PUT', 'DELETE'], 
  allowedHeaders: ['Content-Type', 'Authorization'],
};

app.use(cors(corsOptions));

app.use(express.json()); // Middleware para analisar JSON

// ==================
// Definição dos Esquemas e Modelos
// ==================

// Esquema de Usuários
const userSchema = new mongoose.Schema({
  username: String,
  password: String, // Será armazenada como hash
  email: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);

// Esquema de Dispositivos
const deviceSchema = new mongoose.Schema({
  deviceId: { type: String, unique: true }, // ID único do ESP32
  userId: mongoose.Schema.Types.ObjectId, // Referência ao usuário
  deviceName: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const Device = mongoose.model('Device', deviceSchema);

// Esquema de Leituras
const readingSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId, // Referência ao usuário
  deviceId: mongoose.Schema.Types.ObjectId, // Referência ao dispositivo
  timestamp: { type: Date, default: Date.now },
  temperature: Number,
  humidity: Number,
  gasLevel: Number, // Poluição em ppm
  createdAt: { type: Date, default: Date.now },
});

const Reading = mongoose.model('Reading', readingSchema);

// Configuração de chaves secretas e duração dos tokens
const ACCESS_TOKEN_SECRET = 'access_secret_key';
const REFRESH_TOKEN_SECRET = 'refresh_secret_key';
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

  try {
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
  const user = await User.findOne({ email });

  // Verifica se o usuário existe e se a senha está correta
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Usuário ou senha inválidos' });
  }

  const payload = { userId: user._id, email: user.email, username: user.username };

  const accessToken = generateAccessToken(payload);
  const refreshToken = generateRefreshToken(payload);

  res.json({
    message: 'Login realizado com sucesso',
    accessToken,
    refreshToken
  });
});

// Endpoint de Refresh Token
app.post('/api/refresh', authenticateRefreshToken, async (req, res) => {
  try {
    const { userId } = req.user;
    const user = await User.findOne({ _id: userId });
    const { email, username } = user;
    
    // Gerar um novo accessToken usando os dados do refresh token decodificado
    const newAccessToken = generateAccessToken({ userId, email, username });

    res.json({ accessToken: newAccessToken });
  } catch (err) {
    return res.status(403).json({ error: 'Refresh token inválido' });
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

    if(email) {
      const existingUser = await User.findOne({ email});

      if (existingUser && existingUser._id != id) {
        return res.status(400).json({ error: 'Email já cadastrado' });
      }

      user.email = email;
    }

    // atualiza outros dados do usuário, se houverem
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

// Registro de dispositivo (com lógica para reutilizar ID)
app.post('/api/devices', authenticateToken, async (req, res) => {
  const userId = req.user.userId; // Obtém o ID do usuário do token

  try {
    // Procura um dispositivo cujo deviceName (apelido) seja null
    let device = await Device.findOne({ userId, deviceName: null });

    if (!device) {
      // Se não encontrar, cria um novo dispositivo apenas com o deviceId
      const newDevice = new Device({ deviceId: new mongoose.Types.ObjectId().toString(), userId });
      device = await newDevice.save();
    }

    res.status(201).json({
      _id: device._id,
      deviceId: device.deviceId,
      deviceName: device.deviceName,
      userId: device.userId,
      createdAt: device.createdAt,
      updatedAt: device.updatedAt,
      message: "ID de dispositivo obtido com sucesso!"
    });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao registrar ou buscar dispositivo' });
  }
});

// Listar dispositivos de um usuário
app.get('/api/devices/', authenticateToken, async (req, res) => {
  const { userId } = req.user;

  try {
    // Buscando todos os dispositivos do usuário, mas apenas os que têm o campo deviceName
    const devices = await Device.find({
      userId,
      deviceName: { $exists: true, $ne: null }
    });

    res.json(devices);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao listar dispositivos' });
  }
});

// Atualizar dispositivo
app.put('/api/devices/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { deviceId, deviceName } = req.body;
  
  try {
    if(deviceName.length < 3) {
      return res.status(400).json({ error: 'Nome do dispositivo deve ter no mínimo 3 caracteres' });
    }

    const updatedDevice = await Device.findByIdAndUpdate(
      id,
      { deviceId, deviceName, updatedAt: new Date() },
      { new: true }
    );
    
    if (!updatedDevice) {
      return res.status(404).json({ error: 'Dispositivo não encontrado' });
    }
    res.status(200).json(updatedDevice);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao atualizar dispositivo' });
  }
});

// Deletar dispositivo
app.delete('/api/devices/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const deletedDevice = await Device.findByIdAndDelete(id);
    if (!deletedDevice) {
      return res.status(404).json({ error: 'Dispositivo não encontrado' });
    }
    res.status(200).json({ message: 'Dispositivo deletado com sucesso' });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao deletar dispositivo' });
  }
});

// ==================
// Rotas de Leituras
// ==================

// Adicionar leitura de sensor
app.post('/api/readings', authenticateToken, async (req, res) => {
  const { deviceId, temperature, humidity, gasLevel } = req.body;
  const { userId } = req.user;
  const newReading = new Reading({ userId, deviceId, temperature, humidity, gasLevel });

  try {
    const savedReading = await newReading.save();
    res.status(201).json(savedReading);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao salvar leitura' });
  }
});

// Listar leituras de um dispositivo com deviceName
app.get('/api/readings/:deviceId', authenticateToken, async (req, res) => {
  const { deviceId } = req.params;

  try {
    // Encontre o dispositivo pelo deviceId para obter o deviceName
    const device = await Device.findById(deviceId);
    if (!device) {
      return res.status(404).json({ error: 'Dispositivo não encontrado' });
    }

    const readings = await Reading.find({ deviceId });
    // Adicione o deviceName a cada leitura retornada
    const readingsWithDeviceName = readings.map((reading) => ({
      ...reading.toObject(),
      deviceName: device.deviceName
    }));

    res.json(readingsWithDeviceName);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao listar leituras' });
  }
});

// Listar todas leituras de um usuario com paginação e filtro de data
app.get('/api/readings-filtered/', authenticateToken, async (req, res) => {
  const { userId } = req.user;
  const { page = 1, limit = 10, days } = req.query;

  const skip = (page - 1) * parseInt(limit);
  const query = { userId };

  // Se `days` não for "*", aplica o filtro de data
  if (days && days !== "*") {
    const dateFrom = new Date();
    dateFrom.setDate(dateFrom.getDate() - parseInt(days));
    query.createdAt = { $gte: dateFrom };
  }

  try {
    // Busca as leituras com paginação e filtro de data opcional
    const readings = await Reading.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
      
    // Obtém a contagem total de leituras para a paginação
    const totalReadings = await Reading.countDocuments(query);
    const totalPages = Math.ceil(totalReadings / limit);
    
    // Responde com as leituras e metadados de paginação
    res.json({
      items: readings,
      totalPages,
      currentPage: parseInt(page),
    });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao listar leituras' });
  }
});

app.get('/api/readings/', authenticateToken, async (req, res) => {
  const { userId } = req.user;
  
  try {
    const readings = await Reading.find({ userId });
    res.json(readings);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao listar leituras' });
  }
});

// ==================
// Inicialização do Servidor
// ==================
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});

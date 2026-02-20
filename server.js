require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Client } = require('ssh2');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.text({ type: '*/*' }));

const PORT = process.env.PORT || 3016;

// ==================== SSH HELPER (stateless) ====================
function executeSSH(config, callback) {
  const conn = new Client();

  const sshConfig = {
    host: config.host,
    port: config.port || 22,
    username: config.username,
    password: config.password,
    readyTimeout: 20000,
    algorithms: {
      kex: [
        'curve25519-sha256', 'curve25519-sha256@libssh.org',
        'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521',
        'diffie-hellman-group-exchange-sha256',
        'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512',
        'diffie-hellman-group14-sha256', 'diffie-hellman-group14-sha1',
      ],
      serverHostKey: [
        'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521',
        'rsa-sha2-512', 'rsa-sha2-256', 'ssh-rsa'
      ],
      cipher: [
        'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com',
        'aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-cbc', 'aes256-cbc'
      ]
    }
  };

  return new Promise((resolve, reject) => {
    conn.on('ready', async () => {
      try {
        const result = await callback(conn);
        resolve(result);
      } catch (err) {
        reject(err);
      } finally {
        conn.end();
      }
    });
    conn.on('error', (err) => reject(err));
    conn.connect(sshConfig);
  });
}

// ==================== EXEC HELPER ====================
// Универсальный запуск команды: захватывает stdout + stderr, возвращает exit code.
// cwd — опциональная рабочая директория (cd && command выполняются в одной subshell).
function runCommand(conn, command, cwd = null) {
  return new Promise((resolve, reject) => {
    const fullCommand = cwd
      ? `cd "${cwd}" && ${command}`
      : command;

    conn.exec(fullCommand, { pty: false }, (err, stream) => {
      if (err) return reject(err);

      let stdout = '';
      let stderr = '';

      stream.on('data', (data) => { stdout += data.toString(); });
      stream.stderr.on('data', (data) => { stderr += data.toString(); });
      stream.on('close', (code) => { resolve({ stdout, stderr, code }); });
    });
  });
}

// ==================== AUTH MIDDLEWARE ====================
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers['x-ssh-auth'];
  if (!authHeader) return res.status(401).json({ error: 'Missing x-ssh-auth header' });

  try {
    const decoded = JSON.parse(Buffer.from(authHeader, 'base64').toString('utf-8'));
    if (!decoded.host || !decoded.username || !decoded.password) throw new Error('Invalid auth payload');
    req.sshConfig = decoded;
    next();
  } catch (e) {
    res.status(400).json({ error: 'Invalid auth header format' });
  }
};

app.use(authMiddleware);

// ==================== FILE SYSTEM ROUTES ====================

// 1. Получить структуру файлов (Stateless)
app.get('/api/files', async (req, res) => {
  const targetPath = req.query.path || '.';

  try {
    const files = await executeSSH(req.sshConfig, (conn) => {
      return new Promise((resolve, reject) => {
        conn.sftp((err, sftp) => {
          if (err) return reject(err);
          const allFiles = [];

          const readDirRecursive = (dirPath) => {
            return new Promise((res, rej) => {
              sftp.readdir(dirPath, (err, list) => {
                if (err) return res([]);
                const promises = list.map(item => {
                  const fullPath = path.posix.join(dirPath, item.filename);
                  const type = item.longname.startsWith('d') ? 'directory' : 'file';
                  allFiles.push({ name: item.filename, path: fullPath, type: type });
                  if (type === 'directory') return readDirRecursive(fullPath);
                  return Promise.resolve();
                });
                Promise.all(promises).then(() => res()).catch(rej);
              });
            });
          };
          readDirRecursive(targetPath).then(() => resolve(allFiles)).catch(reject);
        });
      });
    });
    res.json({ files });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2. Прочитать файл
app.get('/api/file', async (req, res) => {
  const filePath = req.query.path;
  if (!filePath) return res.status(400).json({ error: 'Path required' });

  try {
    const content = await executeSSH(req.sshConfig, (conn) => {
      return new Promise((resolve, reject) => {
        conn.sftp((err, sftp) => {
          if (err) return reject(err);
          let data = '';
          const stream = sftp.createReadStream(filePath);
          stream.on('data', chunk => data += chunk);
          stream.on('end', () => resolve(data));
          stream.on('error', reject);
        });
      });
    });
    res.send(content);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 3. Создать папку
app.post('/api/folder', async (req, res) => {
  const dirPath = req.query.path;
  if (!dirPath) return res.status(400).json({ error: 'Path required' });

  try {
    await executeSSH(req.sshConfig, (conn) => {
      return new Promise((resolve, reject) => {
        conn.exec(`mkdir -p "${dirPath}"`, (err, stream) => {
          if (err) return reject(err);
          stream.on('data', () => {});
          stream.stderr.on('data', () => {});
          stream.on('close', (code) => {
            if (code !== 0) return reject(new Error(`mkdir failed with code ${code}`));
            resolve();
          });
        });
      });
    });
    res.json({ success: true, message: 'Folder created' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 4. Записать/Создать файл
app.post('/api/file', async (req, res) => {
  const filePath = req.query.path;
  const content = req.body;
  if (!filePath) return res.status(400).json({ error: 'Path required' });

  try {
    await executeSSH(req.sshConfig, (conn) => {
      return new Promise((resolve, reject) => {
        conn.sftp((err, sftp) => {
          if (err) return reject(err);
          const stream = sftp.createWriteStream(filePath);
          stream.write(content);
          stream.end();
          stream.on('close', resolve);
          stream.on('error', reject);
        });
      });
    });
    res.json({ success: true, message: 'File saved' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 5. Удаление файла или папки
app.delete('/api/file', async (req, res) => {
  const itemPath = req.query.path;
  if (!itemPath) return res.status(400).json({ error: 'Path required' });

  try {
    await executeSSH(req.sshConfig, (conn) => {
      return new Promise((resolve, reject) => {
        conn.sftp((err, sftp) => {
          if (err) return reject(err);
          sftp.stat(itemPath, (err, stats) => {
            if (err) return reject(err);
            if (stats.isDirectory()) {
              conn.exec(`rm -rf "${itemPath}"`, (err, stream) => {
                if (err) return reject(err);
                stream.on('close', resolve);
              });
            } else {
              sftp.unlink(itemPath, (err) => err ? reject(err) : resolve());
            }
          });
        });
      });
    });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 6. Переименование / Перемещение
app.put('/api/file/rename', async (req, res) => {
  const { oldPath, newPath } = req.body;
  if (!oldPath || !newPath) return res.status(400).json({ error: 'Paths required' });

  try {
    await executeSSH(req.sshConfig, (conn) => {
      return new Promise((resolve, reject) => {
        conn.sftp((err, sftp) => {
          if (err) return reject(err);
          sftp.rename(oldPath, newPath, (err) => err ? reject(err) : resolve());
        });
      });
    });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 7. Копирование
app.post('/api/file/copy', async (req, res) => {
  const { source, destination } = req.body;
  if (!source || !destination) return res.status(400).json({ error: 'Source and Destination required' });

  try {
    await executeSSH(req.sshConfig, (conn) => {
      return new Promise((resolve, reject) => {
        conn.exec(`cp -r "${source}" "${destination}"`, (err, stream) => {
          if (err) return reject(err);
          let stderr = '';
          stream.stderr.on('data', (data) => stderr += data);
          stream.on('close', (code) => {
            if (code !== 0) return reject(new Error(`Copy failed: ${stderr}`));
            resolve();
          });
        });
      });
    });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== TERMINAL ROUTE ====================

// 8. Выполнить команду и получить вывод
// Body : { command: "npm run build", cwd: "/home/user/project" }
// Query: ?timeout=30  (секунды, максимум 120)
// Response: { success, code, stdout, stderr }
app.post('/api/exec', async (req, res) => {
  const { command, cwd } = req.body;
  if (!command) return res.status(400).json({ error: 'command required' });

  // Минимальная защита: блокируем команды, очевидно разрушительные для хоста
  const blocked = [
    /rm\s+-rf\s+\/\s*$/,   // rm -rf /
    /mkfs\./,              // форматирование
    /dd\s+if=.*of=\/dev/   // запись на блочное устройство
  ];
  if (blocked.some(rx => rx.test(command))) {
    return res.status(403).json({ error: 'Command blocked for safety reasons' });
  }

  const timeoutMs = Math.min(parseInt(req.query.timeout || '30') * 1000, 120000);

  try {
    const result = await Promise.race([
      executeSSH(req.sshConfig, (conn) => runCommand(conn, command, cwd || null)),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error(`Command timed out after ${timeoutMs / 1000}s`)), timeoutMs)
      )
    ]);

    res.json({
      success: result.code === 0,
      code:    result.code,
      stdout:  result.stdout,
      stderr:  result.stderr
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== GIT ROUTES ====================
// Все маршруты принимают { repoPath } — абсолютный путь к директории репозитория.

// Вспомогательная функция
function gitRun(sshConfig, repoPath, gitArgs) {
  return executeSSH(sshConfig, (conn) => runCommand(conn, `git ${gitArgs}`, repoPath));
}

// 9. Статус репозитория
// Response: { branch, ahead, behind, staged, unstaged, untracked, clean }
app.post('/api/git/status', async (req, res) => {
  const { repoPath } = req.body;
  if (!repoPath) return res.status(400).json({ error: 'repoPath required' });

  try {
    const [v1, v2] = await Promise.all([
      gitRun(req.sshConfig, repoPath, 'status --porcelain=v1'),
      gitRun(req.sshConfig, repoPath, 'status --porcelain=v2 --branch')
    ]);

    // Парсим ветку и ahead/behind
    let branch = 'HEAD', ahead = 0, behind = 0;
    for (const line of v2.stdout.split('\n')) {
      if (line.startsWith('# branch.head')) branch = line.split(' ')[2] || 'HEAD';
      if (line.startsWith('# branch.ab')) {
        const p = line.split(' ');
        ahead  = parseInt(p[2]?.replace('+', '') || '0');
        behind = parseInt(p[3]?.replace('-', '') || '0');
      }
    }

    // Парсим файлы
    const staged = [], unstaged = [], untracked = [];
    for (const line of v1.stdout.split('\n')) {
      if (!line) continue;
      const xy   = line.substring(0, 2);
      const file = line.substring(3);
      if (line.startsWith('??'))                        { untracked.push(file); continue; }
      if (xy[0] !== ' ' && xy[0] !== '?') staged.push({ status: xy[0], file });
      if (xy[1] !== ' ' && xy[1] !== '?') unstaged.push({ status: xy[1], file });
    }

    res.json({
      success: true,
      branch, ahead, behind,
      staged, unstaged, untracked,
      clean: staged.length === 0 && unstaged.length === 0 && untracked.length === 0
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 10. История коммитов
// Query: ?limit=50
app.post('/api/git/log', async (req, res) => {
  const { repoPath } = req.body;
  const limit = Math.min(parseInt(req.query.limit || '50'), 200);
  if (!repoPath) return res.status(400).json({ error: 'repoPath required' });

  try {
    // \x1F (unit separator) безопасен внутри git format
    const result = await gitRun(
      req.sshConfig, repoPath,
      `log --max-count=${limit} --format="%H%x1F%h%x1F%an%x1F%ae%x1F%ai%x1F%s%x1F%D"`
    );

    const commits = result.stdout.trim().split('\n').filter(Boolean).map(line => {
      const [hash, shortHash, authorName, authorEmail, date, subject, refs] = line.split('\x1f');
      return { hash, shortHash, authorName, authorEmail, date, subject, refs };
    });

    res.json({ success: true, commits });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 11. Diff
// Body: { repoPath, filePath?, staged? }
// staged: true — показать diff того что уже в staging area (git diff --cached)
app.post('/api/git/diff', async (req, res) => {
  const { repoPath, filePath, staged = false } = req.body;
  if (!repoPath) return res.status(400).json({ error: 'repoPath required' });

  try {
    const stagedFlag = staged ? '--cached ' : '';
    const target     = filePath ? `-- "${filePath}"` : '';
    const result     = await gitRun(req.sshConfig, repoPath, `diff ${stagedFlag}${target}`);
    res.json({ success: true, diff: result.stdout });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 12. Stage файлов (git add)
// Body: { repoPath, files: ["src/a.ts"] } — пустой массив = git add -A
app.post('/api/git/add', async (req, res) => {
  const { repoPath, files } = req.body;
  if (!repoPath) return res.status(400).json({ error: 'repoPath required' });

  try {
    const targets = (files && files.length > 0)
      ? files.map(f => `"${f}"`).join(' ')
      : '-A';
    const result = await gitRun(req.sshConfig, repoPath, `add ${targets}`);
    res.json({ success: result.code === 0, stderr: result.stderr });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 13. Unstage файлов (git restore --staged)
// Body: { repoPath, files: ["src/a.ts"] }
app.post('/api/git/unstage', async (req, res) => {
  const { repoPath, files } = req.body;
  if (!repoPath || !files?.length) return res.status(400).json({ error: 'repoPath and files required' });

  try {
    const targets = files.map(f => `"${f}"`).join(' ');
    const result  = await gitRun(req.sshConfig, repoPath, `restore --staged ${targets}`);
    res.json({ success: result.code === 0, stderr: result.stderr });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 14. Commit
// Body: { repoPath, message, authorName?, authorEmail? }
app.post('/api/git/commit', async (req, res) => {
  const { repoPath, message, authorName, authorEmail } = req.body;
  if (!repoPath || !message) return res.status(400).json({ error: 'repoPath and message required' });

  try {
    const safeMsg    = message.replace(/"/g, '\\"');
    const authorFlag = (authorName && authorEmail)
      ? `--author="${authorName} <${authorEmail}>" `
      : '';
    const result = await gitRun(req.sshConfig, repoPath, `commit ${authorFlag}-m "${safeMsg}"`);
    res.json({ success: result.code === 0, stdout: result.stdout, stderr: result.stderr });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 15. Push
// Body: { repoPath, remote?: "origin", branch?: "" }
app.post('/api/git/push', async (req, res) => {
  const { repoPath, remote = 'origin', branch = '' } = req.body;
  if (!repoPath) return res.status(400).json({ error: 'repoPath required' });

  try {
    const result = await gitRun(req.sshConfig, repoPath, `push ${remote} ${branch}`.trim());
    res.json({ success: result.code === 0, stdout: result.stdout, stderr: result.stderr });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 16. Pull
// Body: { repoPath, remote?: "origin", branch?: "", rebase?: false }
app.post('/api/git/pull', async (req, res) => {
  const { repoPath, remote = 'origin', branch = '', rebase = false } = req.body;
  if (!repoPath) return res.status(400).json({ error: 'repoPath required' });

  try {
    const rebaseFlag = rebase ? '--rebase ' : '';
    const result = await gitRun(req.sshConfig, repoPath, `pull ${rebaseFlag}${remote} ${branch}`.trim());
    res.json({ success: result.code === 0, stdout: result.stdout, stderr: result.stderr });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 17. Список веток
// Query: ?all=true — включая remote-ветки
app.post('/api/git/branches', async (req, res) => {
  const { repoPath } = req.body;
  if (!repoPath) return res.status(400).json({ error: 'repoPath required' });

  const allFlag = req.query.all === 'true' ? '-a ' : '';

  try {
    const result = await gitRun(
      req.sshConfig, repoPath,
      `branch ${allFlag}--format="%(refname:short)|%(objectname:short)|%(upstream:short)|%(HEAD)"`
    );

    const branches = result.stdout.trim().split('\n').filter(Boolean).map(line => {
      const [name, hash, upstream, current] = line.split('|');
      return { name, hash, upstream: upstream || null, current: current === '*' };
    });

    res.json({ success: true, branches });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 18. Переключение ветки / создание новой
// Body: { repoPath, branch, create?: false }
app.post('/api/git/checkout', async (req, res) => {
  const { repoPath, branch, create = false } = req.body;
  if (!repoPath || !branch) return res.status(400).json({ error: 'repoPath and branch required' });

  try {
    const createFlag = create ? '-b ' : '';
    const result = await gitRun(req.sshConfig, repoPath, `checkout ${createFlag}"${branch}"`);
    res.json({ success: result.code === 0, stdout: result.stdout, stderr: result.stderr });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 19. Stash
// Body: { repoPath, action: "push"|"pop"|"list"|"drop"|"show", message? }
app.post('/api/git/stash', async (req, res) => {
  const { repoPath, action = 'push', message } = req.body;
  if (!repoPath) return res.status(400).json({ error: 'repoPath required' });

  const allowed = ['push', 'pop', 'list', 'drop', 'show'];
  if (!allowed.includes(action)) return res.status(400).json({ error: 'Invalid stash action' });

  try {
    let cmd = `stash ${action}`;
    if (action === 'push' && message) cmd += ` -m "${message.replace(/"/g, '\\"')}"`;
    const result = await gitRun(req.sshConfig, repoPath, cmd);
    res.json({ success: result.code === 0, stdout: result.stdout, stderr: result.stderr });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 20. Проверить / инициализировать репозиторий
// Body: { repoPath, init?: false }
app.post('/api/git/init', async (req, res) => {
  const { repoPath, init = false } = req.body;
  if (!repoPath) return res.status(400).json({ error: 'repoPath required' });

  try {
    if (init) {
      const result = await gitRun(req.sshConfig, repoPath, 'init');
      return res.json({ success: result.code === 0, stdout: result.stdout });
    }
    // Просто проверка: является ли папка git-репозиторием
    const result = await gitRun(req.sshConfig, repoPath, 'rev-parse --is-inside-work-tree');
    res.json({ success: result.code === 0, isRepo: result.stdout.trim() === 'true' });
  } catch (err) {
    res.status(500).json({ error: err.message, isRepo: false });
  }
});

// ==================== START ====================
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Stateless SSH REST API running on port ${PORT}`);
});

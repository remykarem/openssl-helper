/**
 * https://www.digitalocean.com/community/tutorials/openssl-essentials-working-with-ssl-certificates-private-keys-and-csrs
 */

import inquirer from "inquirer";
import cmdify from "cmdify";
import { spawn } from "child_process";

const trimmer = (str) =>
  str
    .replace(/-----BEGIN RSA PRIVATE KEY-----/, "")
    .replace(/-----END RSA PRIVATE KEY-----/, "")
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/-----BEGIN ENCRYPYED PRIVATE KEY-----/, "")
    .replace(/-----END ENCRYPYED PRIVATE KEY-----/, "")
    .replace(/-----BEGIN PUBLIC KEY-----/, "")
    .replace(/-----END PUBLIC KEY-----/, "")
    .replace(/(\r\n|\n|\r)/gm, "");

const convertLong2Pem = () => {
  inquirer
    .prompt([
      {
        type: "list",
        name: "inputType",
        message: "Where is your input?",
        choices: ["clipboard"],
      },
      {
        type: "list",
        name: "privateorpublic",
        message: "What type of PEM is this?",
        choices: [
          "Private key (PKCS #1)",
          "Private key (PKCS #8)",
          "Public key",
          "Certificate",
        ],
      },
      {
        type: "editor",
        name: "toadd",
        message: "Paste it in the editor",
      },
    ])
    .then((answers) => {
      if (answers.privateorpublic === "Private key (PKCS #1)") {
        console.log(
          "-----BEGIN RSA PRIVATE KEY-----\n" +
            answers.toadd.replace(/.{64}/g, "$&\n") +
            "-----END RSA PRIVATE KEY-----\n"
        );
      } else if (answers.privateorpublic === "Private key (PKCS #8)") {
        console.log(
          "-----BEGIN PRIVATE KEY-----\n" +
            answers.toadd.replace(/.{64}/g, "$&\n") +
            "-----END PRIVATE KEY-----\n"
        );
      } else if (answers.privateorpublic === "Certificate") {
        console.log(
          "-----BEGIN CERTIFICATE-----\n" +
            answers.toadd.replace(/.{64}/g, "$&\n") +
            "-----END CERTIFICATE-----\n"
        );
      } else {
        console.log(
          "-----BEGIN PUBLIC KEY-----\n" +
            answers.toadd.replace(/.{64}/g, "$&\n") +
            "-----END PUBLIC KEY-----\n"
        );
      }
    });
};

const convertPem2Long = () => {
  inquirer
    .prompt([
      {
        type: "list",
        name: "inputType",
        message: "Where is your input?",
        choices: ["clipboard"],
      },
      {
        type: "editor",
        name: "totrim",
        message: "Paste it in the editor",
        filter: trimmer,
      },
    ])
    .then((answers) => {
      console.log(answers.totrim);
    });
};

const generateRsaKeyPair = () => {
  const questions = [
    {
      type: "list",
      name: "algo",
      message: "Which algo?",
      choices: ["RSA"],
    },
    {
      type: "list",
      name: "numbits",
      message: "Size of private key (bits)",
      choices: ["1024", "2048", "3072", "4096"],
      default: "2048",
      when(answers) {
        return answers.algo === "RSA";
      },
      validate(value) {
        const valid = !isNaN(parseInt(value));
        if (valid) {
          return true;
        }
        return "Please enter a number";
      },
    },
    {
      type: "confirm",
      name: "toEncryptPrivateKey",
      message: "Encrypt private key?",
      default: false,
    },
    {
      type: "input",
      name: "cipher",
      message: "Cipher:",
      when(answers) {
        return answers.toEncryptPrivateKey;
      },
    },
    {
      type: "list",
      name: "rsaPkcsFormat",
      message: "PKCS format",
      choices: ["PKCS #1", "PKCS #8"],
      default: "PKCS #8",
    },
    {
      type: "list",
      name: "output",
      message: "Output:",
      choices: ["file", "stdout"],
    },
    {
      type: "input",
      name: "filename",
      message: "Name of file:",
      when(answers) {
        return answers.output === "file";
      },
      filter(filename) {
        return filename.endsWith(".pem") ? filename : `${filename}.pem`;
      },
    },
    {
      type: "confirm",
      name: "withPublic",
      message: "Generate public key too?",
    },
  ];

  inquirer.prompt(questions).then((answers) => {
    const commands =
      answers.rsaPkcsFormat === "PKCS #8"
        ? [
            "genpkey",
            "-algorithm",
            answers.algo,
            "-pkeyopt",
            `rsa_keygen_bits:${answers.numbits}`,
          ]
        : ["genrsa", answers.numbits];
    if (answers.output === "file") {
      commands.splice(1, 0, "-out");
      commands.splice(2, 0, answers.filename);
    }
    if (answers.toEncryptPrivateKey) {
      commands.push(`-${answers.cipher}`);
    }

    console.log(commands.join(" "));
    const opensslGenrsa = spawn(cmdify("openssl"), commands);

    opensslGenrsa.stdout.on("data", (data) => {
      console.log(data.toString());
    });

    if (answers.withPublic) {
      opensslGenrsa.on("close", (code) => {
        console.log(code);

        const command = [
          "rsa",
          "-in",
          answers.filename,
          "-pubout",
          "-out",
          answers.filename + ".pub",
        ];

        const opensslRsa = spawn(cmdify("openssl"), command);
        opensslRsa.stdout.on("data", (data) => {
          console.log(`data: ${data}`);
        });
        opensslRsa.stderr.on("data", (data) => {
          console.log(`stdeerr: ${data}`);
        });
        opensslRsa.on("close", () => {
          process.exit();
        });
      });
    }

    console.log(JSON.stringify(answers, null, "  "));
  });
};

const convertPcks1ToPkcs8 = () => {
  inquirer
    .prompt([
      {
        type: "input",
        name: "inputFilename",
        message: "Filename of PKCS #1 private key:",
      },
      {
        type: "input",
        name: "outputFilename",
        message: "Filename of PKCS #8 private key:",
      },
    ])
    .then((answers) => {
      const command = [
        "pkcs8",
        "-topk8",
        "-inform",
        "PEM",
        "-in",
        answers.inputFilename,
        "-out",
        answers.outputFilename,
        "-nocrypt",
      ];

      const openssl = spawn(cmdify("openssl"), command);
      openssl.stdout.on("data", (data) => {
        console.log(data.toString());
      });
      openssl.stderr.on("data", (data) => {
        console.log(data.toString());
      });
    });
};

const convertEncryptedPcks8ToPkcs8 = () => {
  inquirer
    .prompt([
      {
        type: "input",
        name: "inputFilename",
        message: "Filename of encrypted PKCS #8 private key:",
      },
      {
        type: "input",
        name: "outputFilename",
        message: "Filename of output PKCS #8 private key:",
      },
    ])
    .then((answers) => {
      const command = [
        "pkcs8",
        "-topk8",
        "-inform",
        "PEM",
        "-in",
        answers.inputFilename,
        "-out",
        answers.outputFilename,
        "-nocrypt",
      ];

      const openssl = spawn(cmdify("openssl"), command);
      openssl.stdout.on("data", (data) => {
        console.log(data.toString());
      });
      openssl.stderr.on("data", (data) => {
        console.log(data.toString());
      });
    });
};

const comparePrivateAndPublicKeys = () => {
  inquirer

    .prompt([
      {
        type: "input",
        name: "privateFilename",
        message: "Filename of private key:",
      },
      {
        type: "input",
        name: "publicFilename",
        message: "Filename of public key:",
      },
    ])
    .then((answers) => {
      const commandPrivateKey = [
        "rsa",
        "-modulus",
        "-noout",
        "-in",
        answers.privateFilename,
      ];
      const commandPublicKey = [
        "rsa",
        "-modulus",
        "-noout",
        "-pubin",
        "-in",
        answers.publicFilename,
      ];
      console.log(commandPrivateKey.join(" "));
      console.log(commandPublicKey.join(" "));
      const opensslPrivateKey = spawn(cmdify("openssl"), commandPrivateKey);
      const opensslPublicKey = spawn(cmdify("openssl"), commandPublicKey);
      let privateKey = "";
      let publicKey = "";
      opensslPrivateKey.stdout.on("data", (data) => {
        privateKey = data.toString();
      });
      opensslPublicKey.stdout.on("data", (data) => {
        publicKey = data.toString();
      });
      opensslPrivateKey.on("close", () => {
        opensslPublicKey.on("close", () => {
          console.log(`Private key: ${privateKey}`);
          console.log(`Public key: ${publicKey}`);
          if (privateKey === publicKey) {
            console.log("Keys match");
          }
          process.exit();
        });
      });
    });
};

const encodeDecode = () => {
  inquirer.prompt([
    {
      type: "list",
      name: "request",
      message: "What do you want to do?",
      choices: ["encode", "decode"],
    },
    {
      type: "input",
      name: "encode",
      message: "Input:",
      when(answers) {
        return answers.request === "encode";
      },
      filter(input) {
        return Buffer.from(input).toString("base64");
      },
    },
    {
      type: "input",
      name: "decode",
      message: "Input:",
      when(answers) {
        return answers.request === "decode";
      },
      filter(input) {
        return Buffer.from(input, "base64").toString();
      },
    },
  ]);
};

const generateCertificateSigningRequest = () => {
  inquirer
    .prompt([
      {
        type: "list",
        name: "request",
        message: "What do you want to do?",
        choices: [
          "from scratch",
          "from private key",
          "from existing cert and private key",
        ],
      },
    ])
    .then((answers) => {
      if (answers.request === "from scratch") {
        console.log(
          "From scratch: openssl req -newkey rsa:2048 -nodes -keyout domain.key -out domain.csr"
        );
      } else if (answers.request === "from private key") {
        console.log(
          "From private key: openssl req -key domain.key -new -out domain.csr"
        );
      } else if (answers.request === "from existing cert and private key") {
        console.log(
          "From existing cert and private key: openssl x509 -in domain.crt -signkey domain.key -x509toreq -out domain.csr"
        );
      }
    });
};

const generateSelfSignedCertificate = () => {
  inquirer
    .prompt([
      {
        type: "list",
        name: "request",
        message: "What do you want to do?",
        choices: [
          "from scratch",
          "from private key",
          "from csr and private key",
        ],
      },
    ])
    .then((answers) => {
      if (answers.request === "from scratch") {
        console.log(
          "From scratch: openssl req -newkey rsa:2048 -nodes -keyout domain.key -x509 -days 365 -out domain.crt"
        );
      } else if (answers.request === "from private key") {
        console.log(
          "From private key: openssl req -key domain.key -new -x509 -days 365 -out domain.crt"
        );
      } else if (answers.request === "from csr and private key") {
        console.log(
          "From csr and private key: openssl x509 -signkey domain.key -in domain.csr -req -days 365 -out domain.crt"
        );
      }
    });
};

const generateSignature = () => {
  // https://medium.com/@bn121rajesh/rsa-sign-and-verify-using-openssl-behind-the-scene-bf3cac0aade2
  inquirer
    .prompt([
      {
        type: "list",
        name: "request",
        message: "What do you want to do?",
        choices: ["RSASSA-PKCS#1-v1_5"],
      },
      {
        type: "list",
        name: "hashingAlgo",
        message: "Hash algorithm:",
        choices: ["sha256", "sha384", "sha512"],
        default: "sha256",
      },
      {
        type: "input",
        name: "message",
        message: "Message:",
      },
      {
        type: "input",
        name: "filename",
        message: "Enter filename of RSA private key:",
      },
    ])
    .then((answers) => {
      const echo = spawn(cmdify("echo"), ["-n", answers.message]);
      const command = [
        "dgst",
        `-${answers.hashingAlgo}`,
        "-sign",
        answers.filename,
      ];
      const openssl = spawn(cmdify("openssl"), command);
      console.log(command.join(" "));
      const base64 = spawn(cmdify("base64"));

      echo.stdout.pipe(openssl.stdin);
      openssl.stdout.pipe(base64.stdin);

      openssl.stderr.on("data", (data) => {
        console.log(data.toString());
      });
      base64.stdout.on("data", (data) => {
        console.log(data.toString());
      });
    });
};

const generatePublicKey = () => {
  inquirer
    .prompt([
      {
        type: "input",
        name: "filename",
        message: "Enter filename of private key:",
      },
      {
        type: "list",
        name: "output",
        message: "Output to where?",
        choices: ["file", "stdout"],
      },
    ])
    .then((answers) => {
      if (answers.output === "stdout") {
        const command = ["rsa", "-in", answers.filename, "-pubout"];
        const openssl = spawn(cmdify("openssl"), command);
        openssl.stdout.on("data", (data) => {
          console.log(data.toString());
        });
        openssl.stderr.on("data", (data) => {
          console.log(data.toString());
        });
      } else {
        const command = [
          "rsa",
          "-in",
          answers.filename,
          "-pubout",
          "-out",
          answers.filename + ".pub",
        ];
        const openssl = spawn(cmdify("openssl"), command);
        openssl.stdout.on("data", (data) => {
          console.log(answers.filename + ".pub");
          console.log(data.toString());
        });
        openssl.stderr.on("data", (data) => {
          console.log(data.toString());
        });
      }
    });
};

const verifySignature = () => {
  // https://medium.com/@bn121rajesh/rsa-sign-and-verify-using-openssl-behind-the-scene-bf3cac0aade2
  inquirer
    .prompt([
      {
        type: "list",
        name: "hashingAlgo",
        message: "Hash algorithm:",
        choices: ["sha1", "sha256", "sha384", "sha512"],
        default: "sha256",
      },
      {
        type: "input",
        name: "message",
        message: "Message:",
      },
      {
        type: "input",
        name: "signature",
        message: "Signature:",
      },
      {
        type: "input",
        name: "filename",
        message: "Enter filename of public key:",
      },
    ])
    .then((answers) => {
      console.log(
        `openssl dgst -${answers.hashingAlgo} -verify ${answers.filename} -signature <(echo -n "${answers.message}" | base64 -d) myfile.txt`
      );
    });
};

const generateSharedSecret = () => {
  inquirer
    .prompt([
      {
        type: "input",
        name: "numBytes",
        message: "No. of bytes:",
        default: "32",
      },
      {
        type: "list",
        name: "output",
        message: "Output to where?",
        choices: ["file", "stdout"],
      },
      {
        type: "input",
        name: "filename",
        message: "Filename:",
        when(answers) {
          return answers.output === "file";
        },
      },
    ])
    .then((answers) => {
      const command = ["rand", "-base64"];
      if (answers.output === "file") {
        command.push("-out");
        command.push(answers.filename);
      }
      command.push(answers.numBytes);

      const openssl = spawn(cmdify("openssl"), command);
      openssl.stdout.on("data", (data) => {
        console.log(data.toString());
      });
      openssl.stderr.on("data", (data) => {
        console.log(data.toString());
      });
    });
};

const encrypt = () => {
  inquirer
    .prompt([
      {
        type: "input",
        name: "filename",
        message: "File to encrypt:",
      },
      {
        type: "input",
        name: "cipher",
        message: "Cipher:",
        default: "aes-256-cbc",
      },
      {
        type: "confirm",
        name: "hasSharedSecret",
        default: false,
        message: "Got a shared secret?",
      },
      {
        type: "input",
        name: "sharedSecretFile",
        message: "  Shared secret filename:",
        when(answers) {
          return answers.hasSharedSecret;
        },
      },
      {
        type: "list",
        name: "output",
        message: "Output to where?",
        choices: ["file", "stdout"],
        default: "file",
      },
      {
        type: "input",
        name: "outputFile",
        message: "  Output filename (binary):",
        when(answers) {
          return answers.output === "file";
        },
      },
    ])
    .then((answers) => {
      const command = [
        "enc",
        "-in",
        answers.filename,
        `-${answers.cipher}`,
        "-pbkdf2",
      ];

      if (answers.hasSharedSecret) {
        command.push("-pass");
        command.push("file:" + answers.sharedSecretFile);
      }

      if (answers.output === "file") {
        command.push("-out");
        command.push(answers.outputFile);
      } else {
        command.push("-base64");
      }

      console.log(command.join(" "));
      const openssl = spawn(cmdify("openssl"), command);
      openssl.stdout.on("data", (data) => {
        console.log(data.toString());
      });
      openssl.stderr.on("data", (data) => {
        console.log(data.toString());
      });
    });
};

const decrypt = () => {
  inquirer
    .prompt([
      {
        type: "input",
        name: "filename",
        message: "File (binary) to decrypt:",
      },
      {
        type: "input",
        name: "cipher",
        message: "Cipher:",
        default: "aes-256-cbc",
      },
      {
        type: "confirm",
        name: "hasSharedSecret",
        default: false,
        message: "Got a shared secret?",
      },
      {
        type: "input",
        name: "sharedSecretFile",
        message: "  Shared secret filename:",
        when(answers) {
          return answers.hasSharedSecret;
        },
      },
      {
        type: "list",
        name: "output",
        message: "Output to where?",
        choices: ["file", "stdout"],
        default: "file",
      },
      {
        type: "input",
        name: "outputFile",
        message: "  Output filename:",
        when(answers) {
          return answers.output === "file";
        },
      },
    ])
    .then((answers) => {
      const command = [
        "enc",
        "-d",
        "-in",
        answers.filename,
        `-${answers.cipher}`,
        "-pbkdf2",
      ];

      if (answers.hasSharedSecret) {
        command.push("-pass");
        command.push("file:" + answers.sharedSecretFile);
      }

      if (answers.output === "file") {
        command.push("-out");
        command.push(answers.outputFile);
      } else {
        command.push("-base64");
      }

      console.log(command.join(" "));
      const openssl = spawn(cmdify("openssl"), command);
      openssl.stdout.on("data", (data) => {
        console.log(data.toString());
      });
      openssl.stderr.on("data", (data) => {
        console.log(data.toString());
      });
    });
};

inquirer
  .prompt([
    {
      type: "list",
      name: "purpose",
      message: "What can I do for you today?",
      choices: [
        "Generate",
        "Verify",
        "Encrypt/decrypt file",
        "Convert",
        "Compare",
        "Base64-encode/decode",
        "View",
      ],
    },
    {
      type: "list",
      name: "generate",
      message: "Generate:",
      choices: [
        "Key pair",
        "Public key from private key",
        "Shared secret",
        "Signature from private key",
        "Certificate Signing Request",
        "Self-signed certificate",
      ],
      when(answers) {
        return answers.purpose === "Generate";
      },
    },
    {
      type: "list",
      name: "convert",
      message: "Convert:",
      choices: [
        "PEM to long format",
        "Long format to PEM",
        "PKCS #1 to PKCS #8",
        "Encrypted PKCS #8 to PKCS #8",
      ],
      when(answers) {
        return answers.purpose === "Convert";
      },
    },
    {
      type: "list",
      name: "verify",
      message: "Verify:",
      choices: ["Signature"],
      when(answers) {
        return answers.purpose === "Verify";
      },
    },
    {
      type: "list",
      name: "compare",
      message: "Compare:",
      choices: ["Private and public keys"],
      when(answers) {
        return answers.purpose === "Compare";
      },
    },
    {
      type: "list",
      name: "encryptDecrypt",
      message: "Encrypt or decrypt?",
      choices: ["Encrypt", "Decrypt"],
      when(answers) {
        return answers.purpose === "Encrypt/decrypt file";
      },
    },
  ])
  .then((answers) => {
    if (answers.convert === "PEM to long format") {
      convertPem2Long();
    } else if (answers.convert === "Long format to PEM") {
      convertLong2Pem();
    } else if (answers.convert === "PKCS #1 to PKCS #8") {
      convertPcks1ToPkcs8();
    } else if (answers.convert === "Encrypted PKCS #8 to PKCS #8") {
      convertEncryptedPcks8ToPkcs8();
    } else if (answers.purpose === "Base64-encode/decode") {
      encodeDecode();
    } else if (answers.generate === "Certificate Signing Request") {
      generateCertificateSigningRequest();
    } else if (answers.generate === "Self-signed certificate") {
      generateSelfSignedCertificate();
    } else if (answers.generate === "Signature from private key") {
      generateSignature();
    } else if (answers.generate === "Public key from private key") {
      generatePublicKey();
    } else if (answers.generate === "Shared secret") {
      generateSharedSecret();
    } else if (answers.generate === "Key pair") {
      generateRsaKeyPair();
    } else if (answers.verify === "Verify signature") {
      verifySignature();
    } else if (answers.compare === "Private and public keys") {
      comparePrivateAndPublicKeys();
    } else if (answers.encryptDecrypt === "Encrypt") {
      encrypt();
    } else if (answers.encryptDecrypt === "Decrypt") {
      decrypt();
    } else {
      new Error("Unknown purpose");
    }
  });

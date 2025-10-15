# Cryptography

## Vivian Potts (100578802) & Sofia Wu

## Code sharing option

[Indicate whether you’ll share the code via the Google folder or through a GitHub repository. In the last case, specify here the url of the repository and make sure you grant access to the GitHub user linked to email aigonzal@inf.uc3m.es. ]
High-level description of the app
[Describe the application's primary purpose and its key functionalities. Identify the user types the app is designed to serve. Identify the main data flows (e.g., user-to-system, system-to-user, and user-to-user). Describe the data stored by the app and indicate which data should be protected.]
Technical description
Modules
[Describe how the different functionalities are distributed among the different Python scripts. It is highly recommended to include a graphical description besides a textual one.]

## Main functionalities

[Include snapshots of the user interactions with your app (with a brief description) to illustrate the app’s key functionalities.]

## Byte-like/text-like data encoding/decoding

[Specify how you deal with byte-like/text-like data. Include snapshots of the specific code functions you use to encode/decode byte-like/text-like data. List where and why in the app you apply this type of transformations. ]

## User authentication

[Describe how users are registered and authenticated in the app. Describe how the app stores the user’s credentials and verifies them. Specify the cryptographic algorithm used and the reasons for choosing it. Include snapshots of the code, the content of the file/s (or database) that store the credentials and the interactions for user registration and authentication.]

## Data encryption and authentication

[Describe how data is encrypted and authenticated in the app. Describe how the app stores protected data. Specify the cryptographic algorithm used and the reasons for choosing it. Include snapshots of the code, the content of the file/s (or database) that store the encrypted data and the user interactions linked to the encryption/decryption of this data.]

## Symmetric key management

[List the types of cryptographic keys your app uses. Explain how key management is done (e.g., when keys are created, who creates the keys and how, who can access/use that key and how, whether key rotation is done,... Specify which algorithms are used to generate the keys (e.g., os.urandom or PBKDF2…). Include snapshots of the code, the content of the file/s (or database) that store the keys if they are stored, or any related data needed to use them. Include also snapshots of the user interactions linked to key creation/use if any (note that if these interactions are already described in previous sections you can just reference them from this section; there is no need to include duplicated snapshots).]

## Asymmetric key management

[Specify which users of the app have asymmetric keys. Describe when and how those users get their public/private key pair. Include snapshots of the specific code functions you use to create the keys. Specify what use the keys have in the app (digital signature, for encryption…?).]

## Loading and serializing asymmetric keys/public key certificates

[Explain how the asymmetric keys and/or public key certificates are loaded and serialized in your app. Include snapshots of the code and the contents of the files and of the loaded cryptographic material (in readable format).]

## Digital signatures

[Describe what data is signed in the app, by who and when. Explain how the signed data, the signature and the cryptographic material needed to verify the signature is stored in files and in which format/encoding. Explain how the signature is verified. Include snapshots of the code and the interactions related to generate and verify the signature. Specify the algorithms used and justify the reasons for its selection.]

## Asymmetric encryption / hybrid encryption 

[If it is the case, describe how asymmetric encryption is used in the app. Specify which data  is encrypted asymmetrically, by who and for whom. Specify the algorithm used and the reasons for its selection. Explain how asymmetric encryption helps your app to fulfill its purpose. Include snapshots of the code and the interactions related to the use of asymmetric keys for encryption and decryption.]

## Public key certificates and mini-PKI

[Specify the type of public key certificates used in your app to authenticate the public keys (e.g., self-signed or issued by a mini-PKI). In any case, explain when and how certificates are created, including snapshots of the code, the user interactions (if any) related to its creation and use, and its contents in a readable format. In the case of having deployed a mini-PKI, you should also include a description of how you have deployed the mini-PKI including snapshots of the process and any related file/script you have used (you may include these files/scripts in the submission bundle).]

## Other aspects

[Include here any other aspect not related to the previous sections. Note that in the previous sections you may include other aspects related to the ones described but not specifically listed. This last section (or additional ones you need to add) is for OTHER aspects different from the ones described previously. ]

## Conclusions

[Describe what you have learned and the main challenges you have faced to develop the app. Describe what you have enjoyed (if you have) and what you have suffered most. Analyze if developing the app has helped you to better understand  the topics addressed in the course. ]
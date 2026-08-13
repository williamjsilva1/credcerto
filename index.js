/**
 * CredCerto — Cloud Functions
 * ---------------------------------------------------------------
 * Resolve a limitação do SDK client-side: um administrador não consegue
 * criar a conta de outro usuário pelo navegador sem se autodeslogar no
 * processo. Aqui usamos o Admin SDK (que roda no servidor do Firebase,
 * com privilégios totais) para criar o usuário no Authentication e o
 * perfil correspondente no Firestore, tudo numa única chamada segura.
 *
 * DEPLOY:
 *   1) npm install -g firebase-tools      (se ainda não tiver)
 *   2) firebase login
 *   3) na raiz do projeto: firebase init functions  (escolha "Use an existing project")
 *   4) copie este arquivo para functions/index.js
 *   5) dentro de functions/: npm install firebase-admin firebase-functions
 *   6) firebase deploy --only functions
 *
 * Funciona no plano gratuito (Spark) — não faz chamadas de rede externas.
 */

const functions = require('firebase-functions');
const admin = require('firebase-admin');
admin.initializeApp();

exports.criarUsuarioAdmin = functions.https.onCall(async (data, context) => {
  // 1) precisa estar autenticado
  if (!context.auth) {
    throw new functions.https.HttpsError('unauthenticated', 'Você precisa estar logado.');
  }

  // 2) precisa ser Administrador aprovado (confere no Firestore, nunca confie no cliente)
  const chamadorSnap = await admin.firestore().collection('usuarios').doc(context.auth.uid).get();
  const chamador = chamadorSnap.data();
  if (!chamadorSnap.exists || chamador.perfil !== 'Administrador' || chamador.aprovado !== true) {
    throw new functions.https.HttpsError('permission-denied', 'Apenas administradores aprovados podem criar usuários.');
  }

  const { nome, email, senha, perfil, cobradorId, acessoTodasCarteiras, carteiraIds } = data;

  if (!nome || !email || !senha || senha.length < 6) {
    throw new functions.https.HttpsError('invalid-argument', 'Preencha nome, e-mail e uma senha com ao menos 6 caracteres.');
  }

  // 3) cria a conta no Authentication
  let novoUsuarioAuth;
  try {
    novoUsuarioAuth = await admin.auth().createUser({
      email,
      password: senha,
      displayName: nome,
    });
  } catch (e) {
    if (e.code === 'auth/email-already-exists') {
      throw new functions.https.HttpsError('already-exists', 'Já existe uma conta com este e-mail.');
    }
    throw new functions.https.HttpsError('internal', 'Não foi possível criar a conta: ' + e.message);
  }

  // 4) cria o perfil no Firestore — já nasce aprovado, pois foi o próprio admin quem criou
  await admin.firestore().collection('usuarios').doc(novoUsuarioAuth.uid).set({
    nome,
    email,
    senha: null,
    viaGoogle: false,
    perfil: perfil || 'Cobrador',
    cobradorId: cobradorId || null,
    acessoTodasCarteiras: !!acessoTodasCarteiras,
    carteiraIds: carteiraIds || [],
    ativo: true,
    aprovado: true,
    criadoPor: context.auth.uid,
    criadoEm: admin.firestore.FieldValue.serverTimestamp(),
    ultimoAcesso: null,
  });

  return { uid: novoUsuarioAuth.uid };
});

/**
 * Bônus: exclusão "completa" de usuário — remove tanto o perfil no Firestore
 * quanto a conta no Authentication (o app hoje só remove o perfil, pois o
 * SDK client-side não pode apagar a conta de outra pessoa).
 */
exports.excluirUsuarioAdmin = functions.https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError('unauthenticated', 'Você precisa estar logado.');
  }
  const chamadorSnap = await admin.firestore().collection('usuarios').doc(context.auth.uid).get();
  const chamador = chamadorSnap.data();
  if (!chamadorSnap.exists || chamador.perfil !== 'Administrador' || chamador.aprovado !== true) {
    throw new functions.https.HttpsError('permission-denied', 'Apenas administradores aprovados podem excluir usuários.');
  }
  const { uid } = data;
  if (!uid) throw new functions.https.HttpsError('invalid-argument', 'uid é obrigatório.');
  if (uid === context.auth.uid) {
    throw new functions.https.HttpsError('failed-precondition', 'Você não pode excluir sua própria conta.');
  }

  await admin.firestore().collection('usuarios').doc(uid).delete();
  try { await admin.auth().deleteUser(uid); } catch (e) { /* conta já pode não existir mais */ }

  return { ok: true };
});

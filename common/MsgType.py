# MsgType.py
# Tipos de mensagem possíveis que viajam entre cliente e servidor

from enum import Enum


# ─── Tipos de mensagem possíveis ──────────────────────────────────────────────

class MsgType(str, Enum):

    # Comandos

    # Cliente → Servidor

    # ── Comandos de autenticação ────────────────────────────────────────────────

    LOGIN          = "LOGIN"             # pedido de login
    REGISTO        = "REGISTO"           # registo de novo utilizador
    LOGOUT         = "LOGOUT"            # terminar sessão

    # ── Comandos de gestão de contactos e mensagens ─────────────────────────────

    ADD            = "ADD"               # adicionar contacto
    REMOVE         = "REMOVE"            # remover contacto
    LIST           = "LIST"              # pedir lista de utilizadores online
    CONTACTS       = "CONTACTS"          # pedir lista de contactos

    # ── Comandos de gestão de chats ───────────────────────────────

    CHAT          = "CHAT"               # pedir histórico de mensagens de um chat e assinalar entrada
    CHAT_LEAVE    = "CHAT_LEAVE"         # assinalar que saímos da vista de chat daquele utilizador
    SEND          = "SEND"               # enviar mensagem a outro utilizador
    GROUP_SEND    = "GROUP_SEND"         # enviar mensagem a um grupo (payload cifrado)
    GROUP_RECEIVE = "GROUP_RECEIVE"      # mensagem de grupo recebida (push servidor -> cliente)
    GROUP_ACK     = "GROUP_ACK"          # confirmação de recepção de mensagem de grupo
    GROUP_SK_DIST = "GROUP_SK_DIST"     # distribuição de sender key via canal E2E par-a-par

    # ── Comandos de gestão de grupos de chat ─────────────────────────────────

    GROUP            = "GROUP"             # criar grupo de chat
    DELETE_GROUP     = "DELETE_GROUP"      # apagar grupo de chat (só o dono)
    LEAVE            = "LEAVE"             # sair de grupo de chat
    GROUPS           = "GROUPS"            # pedir lista de grupos de chat
    ACCEPT_GROUP     = "ACCEPT_GROUP"      # aceitar convite para grupo de chat
    REJECT_GROUP     = "REJECT_GROUP"      # rejeitar convite para grupo
    GROUP_INVITES    = "GROUP_INVITES"     # pedir lista de convites para grupos de chat
    GROUP_ADD_MEMBER  = "GROUP_ADD_MEMBER"   # dono adiciona membro ao grupo (via convite)
    GROUP_KICK_MEMBER = "GROUP_KICK_MEMBER"  # dono remove membro do grupo
    GROUP_MEMBER_LEFT = "GROUP_MEMBER_LEFT"  # servidor notifica membros remanescentes de saída/expulsão
    GROUP_MEMBER_JOINED = "GROUP_MEMBER_JOINED"  # servidor notifica membros existentes de entrada de novo membro

    # ── E2E (prekeys descentralizadas, symmetric ratchet) ─────────────────────
    PREKEY_UPLOAD   = "PREKEY_UPLOAD"    # cliente envia lista de prekeys ao servidor após login
    PREKEY_REQUEST  = "PREKEY_REQUEST"   # cliente pede prekey + cert de outro utilizador
    PREKEY_BUNDLE   = "PREKEY_BUNDLE"    # servidor responde com prekey + cert (B offline)
    ONLINE_BUNDLE   = "ONLINE_BUNDLE"    # servidor responde com cert (B online, DH direto)
    E2E_MSG         = "E2E_MSG"          # cliente envia blob E2E ao servidor (relay opaco)
    E2E_DELIVER     = "E2E_DELIVER"      # servidor entrega blob E2E ao destinatário (push)
    E2E_ACK         = "E2E_ACK"         # cliente confirma recepção de blob E2E
    CERT_REQUEST    = "CERT_REQUEST"     # cliente pede certificado de outro utilizador

    # Servidor → Cliente
    OK       = "OK"                      # resposta de sucesso
    ERROR    = "ERROR"                   # resposta de erro
    RECEIVE  = "RECEIVE"                 # mensagem recebida de outro utilizador/grupo

    # ── Comandos de gestão de chaves e segurança ───────────────────────────────

    # Cliente → Servidor
    PUBLIC_KEY     = "PUBLIC_KEY"        # enviar chave pública para o servidor

    
    # Servidor → Cliente
    PUBLIC_KEY_REQ = "PUBLIC_KEY_REQ"    # pedido de chave pública de outro utiliz

    # ── Renegociação DH (tratada na camada de rede, invisível à lógica de negócio)
    REKEY          = "REKEY"             # renegociação de chaves DH
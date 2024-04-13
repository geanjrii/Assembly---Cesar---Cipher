.686
.model flat, stdcall
option casemap:none

include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\masm32.inc
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\masm32.lib


.data?
  outHandle dd ?
  inHandle dd ?
  outFileHandle dd ?
  inFileHandle dd ?
  consoleCount dd ?
  fileInTransferCount dd ?
  fileOutTransferCount dd ?
  opcaoEscolhida dd ?  
  chave dd ?
  chaveAnalise dd ?
  

.data
  msg_boasvindas db "***Bem-vindo(a) ao Programa CIFRA DE CESAR!***",0AH,0H
  msg_opcoes db 0AH,"--Op",135,228,"es:--",0AH,"1. Criptografar",0AH,"2. Descriptografar",0AH,"3. Criptoan",160,"lise",0AH,"4. Sair",0AH,"Sua opcao: ",0H
  msg_invalida db "A opcao digitada nao eh valida. Por favor, digite uma das opcoes valida.",0AH,0H
  msg_arq_entrada db 0AH,"Digite o nome do arquivo de entrada (max 50 caracteres): ",0H
  msg_arq_saida db "Digite o nome do arquivo de saida (max 50 caracteres): ", 0H
  msg_chave db "Digite uma chave (de 1 a 20): ",0H
  chave_highscore_str db 0AH,"Chave mais provavel utilizada: ",0H
  pular_linha_str db 0AH,0H
  bufferSaida db 100 dup(0)
  input_chave db 6 dup(0)
  input_opcao db 4 dup(0)
  input_arq_entrada db 53 dup(0)
  input_arq_saida db 53 dup(0)
  fileBuffer db 512 dup(0)
  asciiEstendida dd 256 dup(0)
  highScore dd 0
  chaveHighScore dd 0
   

.code
TratarEntrada:
; EBP+8: Endereco da string
  push ebp
  mov ebp, esp

  mov esi, [ebp+8] ; Armazenar apontador da string em esi
_proximo:
  mov al, [esi] ; Mover caractere atual para al
  inc esi ; Apontar para o proximo caractere
  cmp al, 13 ; Verificar se eh o caractere ASCII CR - FINALIZAR
  jne _proximo
  dec esi ; Apontar para caractere anterior
  xor al, al ; ASCII 0
  mov [esi], al ; Inserir ASCII 0 no lugar do ASCII CR

  mov esp, ebp
  pop ebp
  ret 4

CifrarBuffer:
; EBP+8: Endereco do buffer
; EBP+12: Tamanho do buffer
; EBP+16: Chave
   push ebp
   mov ebp, esp
  
   mov ebx, [ebp+8]
   mov ecx, [ebp+12]
 continuarBufferCripto:
   dec ecx
   mov eax, [ebp+16]
   add [ebx + ecx], al
   cmp ecx, 0
   jge continuarBufferCripto

   mov esp, ebp
   pop ebp
   ret 12

DecifrarBuffer:
; EBP+8: Endereco do buffer
; EBP+12: Tamanho do buffer
; EBP+16: Chave

  push ebp
  mov ebp, esp

  mov ebx, [ebp+8]
  mov ecx, [ebp+12]
continuarBufferDescripto:
  dec ecx
  mov eax, [ebp+16]
  sub [ebx + ecx], al
  cmp ecx, 0
  jge continuarBufferDescripto

  mov esp, ebp
  pop ebp
  ret 12

ReceberNomeArqEntrada:
  invoke WriteConsole, outHandle, offset msg_arq_entrada, sizeof msg_arq_entrada - 1,offset consoleCount, NULL
  invoke ReadConsole, inHandle, offset input_arq_entrada, sizeof input_arq_entrada - 1, offset consoleCount, NULL
  push offset input_arq_entrada
  call TratarEntrada
  ret

ReceberNomeArqSaida:
  invoke WriteConsole, outHandle, offset msg_arq_saida, sizeof msg_arq_saida - 1,offset consoleCount, NULL
  invoke ReadConsole, inHandle, offset input_arq_saida, sizeof input_arq_saida - 1, offset consoleCount, NULL
  push offset input_arq_saida
  call TratarEntrada
  ret

ReceberChave:
  invoke WriteConsole, outHandle, offset msg_chave, sizeof msg_chave - 1,offset consoleCount, NULL
  invoke ReadConsole, inHandle, offset input_chave, sizeof input_chave - 1, offset consoleCount, NULL
  push offset input_chave
  call TratarEntrada
  invoke atodw, offset input_chave
  mov chave, eax
  ret

start:
  invoke GetStdHandle, STD_OUTPUT_HANDLE
  mov outHandle, eax
  invoke GetStdHandle, STD_INPUT_HANDLE
  mov inHandle, eax

  invoke WriteConsole, outHandle, offset msg_boasvindas, sizeof msg_boasvindas - 1,offset consoleCount, NULL
principal:
  invoke WriteConsole, outHandle, offset msg_opcoes, sizeof msg_opcoes - 1,offset consoleCount, NULL
  invoke ReadConsole, inHandle, offset input_opcao, sizeof input_opcao - 1, offset consoleCount, NULL

  push offset input_opcao
  call TratarEntrada
  invoke atodw, offset input_opcao
  mov opcaoEscolhida, eax

  cmp eax, 1
  je criptografar
  cmp eax, 2
  je descriptografar
  cmp eax, 3
  je criptoanalise
  cmp eax, 4
  je sair
  invoke WriteConsole, outHandle, offset msg_invalida, sizeof msg_invalida - 1,offset consoleCount, NULL
  jmp principal

criptografar:
  call ReceberNomeArqEntrada 
  call ReceberNomeArqSaida
  call ReceberChave

  invoke CreateFile, offset input_arq_entrada, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
  mov inFileHandle, eax

  invoke CreateFile, offset input_arq_saida, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
  mov outFileHandle, eax
 
continuarLeituraCripto:
  invoke ReadFile, inFileHandle, offset fileBuffer, 512, offset fileInTransferCount, NULL ; Le 512 bytes do arquivo
  cmp fileInTransferCount, 0
  je arquivoTerminadoCripto

  push DWORD PTR[chave]
  push DWORD PTR[fileInTransferCount]
  push offset fileBuffer
  call CifrarBuffer
 
  invoke WriteFile, outFileHandle, offset fileBuffer, fileInTransferCount, offset fileOutTransferCount, NULL
  jmp continuarLeituraCripto
arquivoTerminadoCripto:
  invoke CloseHandle, inFileHandle
  invoke CloseHandle, outFileHandle
  jmp principal

descriptografar:
  call ReceberNomeArqEntrada   
  call ReceberNomeArqSaida
  call ReceberChave

  invoke CreateFile, offset input_arq_entrada, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
  mov inFileHandle, eax

  invoke CreateFile, offset input_arq_saida, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
  mov outFileHandle, eax
  
continuarLeituraDescripto:
  invoke ReadFile, inFileHandle, offset fileBuffer, 512, offset fileInTransferCount, NULL ; Le 512 bytes do arquivo
  cmp fileInTransferCount, 0
  je arquivoTerminadoDescripto

  push DWORD PTR[chave]
  push DWORD PTR[fileInTransferCount]
  push offset fileBuffer
  call DecifrarBuffer

  invoke WriteFile, outFileHandle, offset fileBuffer, fileInTransferCount, offset fileOutTransferCount, NULL
  jmp continuarLeituraDescripto
arquivoTerminadoDescripto:

  invoke CloseHandle, inFileHandle
  invoke CloseHandle, outFileHandle
  jmp principal

criptoanalise:
  mov chaveAnalise, 0
  mov chaveHighScore, 0
  mov highScore, 0
  
  call ReceberNomeArqEntrada  
  invoke CreateFile, offset input_arq_entrada, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
  mov inFileHandle, eax


analisarChave:
  invoke SetFilePointer, inFileHandle, 0, NULL, FILE_BEGIN
  xor ecx, ecx
limparBuffer:
  mov DWORD PTR [asciiEstendida+ecx*4], 0
  inc ecx
  cmp ecx, 256
  jb limparBuffer
  
  
  
continuarLeituraAnalise:
  invoke ReadFile, inFileHandle, offset fileBuffer, 512, offset fileInTransferCount, NULL ; Le 512 bytes do arquivo
  cmp fileInTransferCount, 0
  je arquivoTerminadoAnalise

  push DWORD PTR[chaveAnalise]
  push DWORD PTR[fileInTransferCount]
  push offset fileBuffer
  call DecifrarBuffer
 
  mov ecx, 0
continuarAnaliseCaracteres:
  xor ebx, ebx
  mov bl, [fileBuffer + ecx]
  inc DWORD PTR[asciiEstendida + ebx*4] ; Incrementar contagem do caractere encontrado
  inc ecx
  cmp ecx, fileInTransferCount
  jb continuarAnaliseCaracteres

  jmp continuarLeituraAnalise

arquivoTerminadoAnalise:    
  ; Instrucoes abaixo adicionam as contagens das versoes acentuadas dos caracteres para a versao sem acentuacao
  ; A = 65, a = 97, â = 131, à = 133, á = 160, Á = 181, Â = 182, À = 183, ã = 198, Ã = 199
  mov eax, DWORD PTR[asciiEstendida+97*4]
  add DWORD PTR[asciiEstendida+65*4], eax
  mov eax, DWORD PTR[asciiEstendida+131*4]
  add DWORD PTR[asciiEstendida+65*4], eax
  mov eax, DWORD PTR[asciiEstendida+133*4]
  add DWORD PTR[asciiEstendida+65*4], eax
  mov eax, DWORD PTR[asciiEstendida+160*4]
  add DWORD PTR[asciiEstendida+65*4], eax
  mov eax, DWORD PTR[asciiEstendida+181*4]
  add DWORD PTR[asciiEstendida+65*4], eax
  mov eax, DWORD PTR[asciiEstendida+182*4]
  add DWORD PTR[asciiEstendida+65*4], eax
  mov eax, DWORD PTR[asciiEstendida+183*4]
  add DWORD PTR[asciiEstendida+65*4], eax
  mov eax, DWORD PTR[asciiEstendida+198*4]
  add DWORD PTR[asciiEstendida+65*4], eax
  mov eax, DWORD PTR[asciiEstendida+199*4]
  add DWORD PTR[asciiEstendida+65*4], eax
  
  ; E = 69, e = 101, é = 130, ê = 136, É = 144, Ê = 210
  mov eax, DWORD PTR[asciiEstendida+101*4]
  add DWORD PTR[asciiEstendida+69*4], eax
  mov eax, DWORD PTR[asciiEstendida+130*4]
  add DWORD PTR[asciiEstendida+69*4], eax
  mov eax, DWORD PTR[asciiEstendida+136*4]
  add DWORD PTR[asciiEstendida+69*4], eax
  mov eax, DWORD PTR[asciiEstendida+144*4]
  add DWORD PTR[asciiEstendida+69*4], eax
  mov eax, DWORD PTR[asciiEstendida+210*4]
  add DWORD PTR[asciiEstendida+69*4], eax

  ; O = 79, o = 111, ô = 147, ó = 162, Ó = 224, Ô = 226
  mov eax, DWORD PTR[asciiEstendida+111*4]
  add DWORD PTR[asciiEstendida+79*4], eax
  mov eax, DWORD PTR[asciiEstendida+147*4]
  add DWORD PTR[asciiEstendida+79*4], eax
  mov eax, DWORD PTR[asciiEstendida+162*4]
  add DWORD PTR[asciiEstendida+79*4], eax
  mov eax, DWORD PTR[asciiEstendida+224*4]
  add DWORD PTR[asciiEstendida+79*4], eax
  mov eax, DWORD PTR[asciiEstendida+226*4]
  add DWORD PTR[asciiEstendida+79*4], eax

  ; Foi criada uma formula (em EAX) para estimar quao perto o texto estah da distribuicao de A's, E's e O's estimada na lingua portuguesa
  ; A = 14,63%, E = 12,57%, O = 10,73% ----> A * 7 + E * 6 + C * 5 / 18
  mov eax, DWORD PTR[asciiEstendida+65*4]
  mov ebx, 7
  mul ebx
  mov ecx, eax
    
  mov eax, DWORD PTR[asciiEstendida+69*4]
  mov ebx, 6
  mul ebx
  add ecx, eax

  mov eax, DWORD PTR[asciiEstendida+79*4]
  mov ebx, 5
  mul ebx
  add ecx, eax

  mov eax, ecx
  xor edx, edx
  mov ebx, 18
  div ebx

  ; Se o resultado da formula, armazenado em EAX, exceder o maior valor da formula jah encontrado ateh agora (highScore) atualizar esse valor com EAX
  cmp eax, highScore
  jbe proximaChave
  mov highScore, eax
  mov eax, chaveAnalise
  mov chaveHighScore, eax ; Guardar o valor da chave que originou o highScore atual

  proximaChave:
  inc chaveAnalise
  mov eax, chaveAnalise
  cmp eax, 20 
  jbe analisarChave ; Testar todas as chaves de 0 a 20
  
  invoke WriteConsole, outHandle, offset chave_highscore_str, sizeof chave_highscore_str -1, offset consoleCount, NULL
  invoke dwtoa, chaveHighScore, offset bufferSaida
  invoke StrLen, offset bufferSaida  
  invoke WriteConsole, outHandle, offset bufferSaida, eax, offset consoleCount, NULL
  invoke WriteConsole, outHandle, offset pular_linha_str, sizeof pular_linha_str -1, offset consoleCount, NULL

  invoke CloseHandle, inFileHandle
  jmp principal
  
sair:
  invoke ExitProcess, 0

end start


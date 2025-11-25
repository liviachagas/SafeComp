# SafeComp – Sistema Desktop em Java com Foco em Segurança e Conversões Numéricas  
Projeto A3 – Sistemas Computacionais e Segurança

## Autores
- Gabriel Bernardino de Araújo – RA 1362521678  
- José Robert Pereira de Andrade – RA 13625111325  
- Lívia Ellen Chagas Lourenço – RA 1362212809  
- Emanuell Átilla Barbosa da Silva – RA 1362521757  

## Orientadores
- Prof. Demetrius De Castro Do Amaral  
- Prof. Pablo Ramon De Lima Pinheiro  

## Unidade Curricular
**Sistemas Computacionais e Segurança**  
Curso: Ciência da Computação  

---

# Introdução
A compreensão dos fundamentos da arquitetura de computadores e da segurança da informação é essencial para a formação em tecnologia. O SafeComp foi desenvolvido para demonstrar, de forma prática, conceitos como conversão numérica, escalonamento de processos e criptografia básica.

---

#  Objetivo
Desenvolver um sistema didático em Java que integre conversão numérica, simulação de processos e segurança da informação, aplicando conteúdos essenciais da área de computação.

---

# Tecnologias Utilizadas
- **Java**
- **Visual Studio Code**
- **Bibliotecas padrão**
- **Git/GitHub**

---

#  Funcionalidades

##  Conversão Numérica
- Binário ↔ Decimal  
- Decimal ↔ Octal  
- Hexadecimal ↔ Decimal  
- Operações booleanas básicas  

##  Simulador de Processos
- FCFS  
- Round Robin  
- Prioridade  

##  Segurança da Informação
- Criptografia (Cifra de César)  
- Hash de senhas  
- Autenticação simples  

---

#  Estrutura do Projeto
/src
/conversao
/processos
/seguranca
Main.java
/docs


---

# Resultados
O SafeComp demonstrou boa estabilidade, interface simples e funcionamento adequado em todos os módulos. Os testes confirmaram compatibilidade e eficiência como ferramenta de aprendizagem.

---

# Considerações Finais
O sistema permitiu visualizar na prática diversos conceitos estudados na disciplina. Futuras melhorias incluem:
- Interface mais moderna  
- Algoritmos de criptografia avançada  
- Mais opções no simulador de processos  

---

# Referências
- ISO/IEC 27001 – *Information Security Management Systems Requirements*:  
  https://www.iso.org/standard/27001.html  

- ISO/IEC 27002 – *Information Security Controls*:  
  https://www.iso.org/standard/75652.html  

- Stallings, William – *Cryptography and Network Security*:  
  https://www.pearson.com/en-us/subject-catalog/p/cryptography-and-network-security/P200000003968  

- Tanenbaum, Andrew S.; Woodhull, Albert – *Sistemas Operacionais Modernos*:  
  https://www.pearson.com/en-us/subject-catalog/p/modern-operating-systems/P200000003971  

- Silberschatz, Abraham; Galvin, Peter; Gagne, Greg – *Operating System Concepts*:  
  https://www.wiley.com/en-us/Operating+System+Concepts%2C+10th+Edition-p-9781119456339  

- Forouzan, Behrouz – *Fundamentos de Redes de Computadores*:  
  https://www.mheducation.com/highered/product/data-communications-networking-forouzan/M9780073376226.html  

**************************************************************************************************************************

Projeto.java

import java.util.Scanner;
import java.util.ArrayList;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Projeto {
    static Scanner entrada = new Scanner(System.in);
    static ArrayList<Usuario> usuarios = new ArrayList<>();

    // variáveis da chave
    private static SecretKey CHAVE_SECRETA;
    private static final String ALGORITMO = "AES";

    static {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITMO);
            keyGen.init(128);
            CHAVE_SECRETA = keyGen.generateKey();
            registrarLog("Chave de criptografia AES gerada com sucesso.");
        } catch (Exception e) {
            System.err.println("Erro fatal ao inicializar a criptografia: " + e.getMessage());
        }
    }

    public static void registrarLog(String mensagem) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("log.txt", true))) {
            LocalDateTime agora = LocalDateTime.now();
            DateTimeFormatter formato = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
            String linha = "[" + agora.format(formato) + "] " + mensagem;
            writer.write(linha);
            writer.newLine();
        } catch (IOException e) {
            System.out.println("Erro ao registrar log: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        try {
            while (true) {
                System.out.println("***** MENU PRINCIPAL *****");
                System.out.println("1 - Fazer login");
                System.out.println("2 - Fazer cadastro");
                System.out.println("3 - Sair");
                System.out.print("Escolha uma opção: ");
                String opcao = entrada.nextLine();

                switch (opcao) {
                    case "1":
                        fazerLogin();
                        break;
                    case "2":
                        fazerCadastro();
                        break;
                    case "3":
                        System.out.println("Encerrando sistema...");
                        registrarLog("Sistema encerrado pelo usuario");
                        return;
                    default:
                        System.out.println("Opção inválida.");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            entrada.close();
        }
    }

    // Criptografando a String
    public static String criptografar(String texto) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITMO);
        cipher.init(Cipher.ENCRYPT_MODE, CHAVE_SECRETA);
        byte[] bytesCriptografados = cipher.doFinal(texto.getBytes());
        return Base64.getEncoder().encodeToString(bytesCriptografados);
    }

    // Descriptografando a String
    public static String descriptografar(String textoCriptografado) throws Exception {
        byte[] bytesCriptografados = Base64.getDecoder().decode(textoCriptografado);
        Cipher cipher = Cipher.getInstance(ALGORITMO);
        cipher.init(Cipher.DECRYPT_MODE, CHAVE_SECRETA);
        byte[] bytesDescriptografados = cipher.doFinal(bytesCriptografados);
        return new String(bytesDescriptografados);
    }

    // ===== INÍCIO DO FAZER LOGIN CORRIGIDO =====
public static void fazerLogin() {
    System.out.println("Nome Completo: ");
    String nome = entrada.nextLine();

    System.out.println("Login: ");
    String login = entrada.nextLine();

    System.out.println("Senha: ");
    String senhaDigitada = entrada.nextLine();

    // Login Admin
    if (login.equals("admin") && senhaDigitada.equals("admin")) {
        System.out.println("Bem vindo, administrador!");
        registrarLog("Admin fez login no sistema.");
        menuAdmin();
        return;
    }

    // Login Usuário Comum
    for (Usuario u : usuarios) {
        if (u.login.equals(login)) {

            // Verifica se está bloqueado
            if (u.bloqueado) {
                System.out.println("Usuário bloqueado! Contate o administrador.");
                registrarLog("Tentativa de login de usuário bloqueado: " + login);
                return;
            }

            try {
                String senhaArmazenada = descriptografar(u.senha);

                if (u.nome.equals(nome) && senhaArmazenada.equals(senhaDigitada)) {
                    u.tentativasErradas = 0; // reseta tentativas
                    System.out.println("Login bem sucedido! Bem vindo, " + u.login);
                    menuUsuario(u);
                    return;
                } else {
                    u.tentativasErradas++; // incrementa tentativas erradas

                    if (u.tentativasErradas >= 3) {
                        u.bloqueado = true; // bloqueia usuário
                        System.out.println("Usuário bloqueado após 3 tentativas incorretas!");
                        registrarLog("Usuário " + u.login + " bloqueado após 3 tentativas falhas.");
                    } else {
                        System.out.println("Nome ou senha incorretos. Tentativa " + u.tentativasErradas + "/3.");
                        registrarLog("Tentativa de login falha para usuário: " + u.login);
                    }
                    return;
                }

            } catch (Exception e) {
                System.out.println("Erro interno ao processar login. (Falha na descriptografia)");
                registrarLog("ERRO CRITICO: Falha na descriptografia do login de " + u.login);
                return;
            }
        }
    }

    System.out.println("Login, nome ou senha incorretos.");
    registrarLog("Tentativa de login falha para usuário não encontrado: " + login);
}
// ===== FIM DO FAZER LOGIN CORRIGIDO =====


    public static void fazerCadastro() {
    System.out.println("Nome completo: ");
    String novoNome = entrada.nextLine();

    System.out.println("Login: ");
    String novoLogin = entrada.nextLine();

    // Verificar se já existe login
    for (Usuario u : usuarios) {
        if (u.login.equals(novoLogin)) {
            System.out.println("Esse login já existe, tente outro.");
            return;
        }
    }

    System.out.println("Senha: ");
    String novaSenha = entrada.nextLine();

    String senhaCriptografada = null;
    try {
        senhaCriptografada = criptografar(novaSenha);  // <-- senha criptografada
    } catch (Exception e) {
        System.out.println("Erro ao criptografar a senha: " + e.getMessage());
        registrarLog("ERRO: Falha na criptografia da senha do usuário " + novoLogin);
        return;
    }

    Usuario novo = new Usuario(novoNome, novoLogin, senhaCriptografada);
    usuarios.add(novo);
    System.out.println("Usuário cadastrado.");
    registrarLog("Novo usuário cadastrado " + novoLogin + " " + novoNome);
}


    public static void menuAdmin() {
        int opcao = -1;
        do {
            System.out.println("\n**** MENU ADMIN ****");
            System.out.println("1 - Criar usuario(s)");
            System.out.println("2 - Listar usuario(s)");
            System.out.println("3 - Enviar mensagem");
            System.out.println("4 - Sair");
            System.out.println("5 - Ver logs do sistema");
            System.out.println("6 - Desbloquear usuarios");
            System.out.print("Escolha uma opção: ");

            try {
                opcao = Integer.parseInt(entrada.nextLine());
            } catch (NumberFormatException e) {
                System.out.println("Opção inválida, digite um número");
                continue;
            }

            switch (opcao) {
                case 1:
                    criarUsuario();
                    registrarLog("Admin criou um usuario");
                    break;
                case 2:
                    listarUsuario();
                    registrarLog("Admin listou os usuarios");
                    break;
                case 3:
                    enviarMensagem();
                    registrarLog("Admin enviou uma mensagem");
                    break;
                case 4:
                    System.out.println("Saindo do menu admin...");
                    registrarLog("Admin saiu do sistema");
                    break;
                case 5:
                    exibirLogs();
                    break;
                case 6:
                    desbloquearUsuario();
                    break;
                default:
                    System.out.println("Opção inválida, tente novamente.");
            }

        } while (opcao != 4);
    }

    public static void criarUsuario() {
        System.out.println("Nome completo do novo usuario: ");
        String nome = entrada.nextLine();

        System.out.println("Novo Login: ");
        String novoLogin = entrada.nextLine();

        for (Usuario u : usuarios) {
            if (u.login.equals(novoLogin)) {
                System.out.println("Esse login já está em uso, tente outro");
                return;
            }
        }

        System.out.println("Nova Senha: ");
        String novaSenha = entrada.nextLine();

        Usuario novo = new Usuario(nome, novoLogin, novaSenha);
        usuarios.add(novo);

        System.out.println("Usuário criado com sucesso!");
        registrarLog("Admin criou o usuario: " + novoLogin + " (" + nome + ")");
    }

    public static void listarUsuario() {
        if (usuarios.isEmpty()) {
            System.out.println("Não há nenhum usuario cadastrado ainda.");
        } else {
            System.out.println("Lista de usuários:");
            for (Usuario u : usuarios) {
                System.out.println("- " + u.login);
            }
        }
    }

    public static void enviarMensagem() {
        System.out.println("Digite o login do usuario destinatario: ");
        String destinatario = entrada.nextLine();

        Usuario user = null;
        for (Usuario u : usuarios) {
            if (u.login.equals(destinatario)) {
                user = u;
                break;
            }
        }

        if (user == null) {
            System.out.println("Usuário não encontrado.");
            return;
        }

        System.out.println("Digite a mensagem: ");
        String texto = entrada.nextLine();
        user.mensagens.add(texto);

        System.out.println("Mensagem enviada.");
    }

    public static void exibirLogs() {
        System.out.println("\n===== LOG DO SISTEMA =====");

        try (Scanner leitor = new Scanner(new java.io.File("log.txt"))) {
            boolean vazio = true;
            while (leitor.hasNextLine()) {
                System.out.println(leitor.nextLine());
                vazio = false;
            }
            if (vazio) {
                System.out.println("(O log está vazio.)");
            }
        } catch (IOException e) {
            System.out.println("Erro ao ler o log: " + e.getMessage());
        }

        System.out.println("\nPressione ENTER para voltar ao menu admin...");
        try {
            System.in.read();
            System.in.skip(System.in.available());
        } catch (IOException e) {
            System.out.println("Erro ao esperar Enter: " + e.getMessage());
        }
    }

    public static void enviarMensagem(String remetente) {
        System.out.println("Digite o login de destino: ");
        String destino = entrada.nextLine();

        Usuario userDest = null;
        for (Usuario u : usuarios) {
            if (u.login.equals(destino)) {
                userDest = u;
                break;
            }
        }

        if (userDest == null) {
            System.out.println("Usuário não encontrado");
            registrarLog("Falha ao enviar mensagem: destinatário " + destino + " não existe. Remetente: " + remetente);
            return;
        }

        System.out.println("Digite a mensagem: ");
        String texto = entrada.nextLine();

        LocalDateTime agora = LocalDateTime.now();
        DateTimeFormatter formato = DateTimeFormatter.ofPattern("yyyy-MM-dd HH-mm-ss");
        String linha = "[" + agora.format(formato) + "] De: " + remetente + " - " + texto;

        userDest.mensagens.add(linha);

        System.out.println("Mensagem enviada.");
        registrarLog("Mensagem enviada de: " + remetente + " para: " + userDest.login);
    }
    public static void verMensagensRecebidas(Usuario usuario) {
        System.out.println("***** MENSAGENS RECEBIDAS *****");
        if (usuario.mensagens.isEmpty()) {
            System.out.println("Você não tem mensagens.");
        } else {
            int i = 1;
         for (String msg : usuario.mensagens) {
            System.out.println(i + " - " + msg);
            i++;
        }
    }

    registrarLog("Usuario " + usuario.login + " visualizou suas mensagens.");
    System.out.println("Pressione ENTER para voltar");
    try {
        System.in.read();
        System.in.skip(System.in.available());
    } catch (IOException e) {
        
    }
    
  }

 public static void alterarSenha(Usuario usuario) {
    System.out.print("Digite sua senha atual: ");
    String atual = entrada.nextLine();

    if (!usuario.senha.equals(atual)) {
        System.out.println("Senha atual incorreta.");
        registrarLog("Tentativa de alteração de senha falhou para " + usuario.login);
        return;
    }

    System.out.print("Digite a nova senha: ");
    String nova = entrada.nextLine();

    usuario.senha = nova;
    System.out.println("Senha alterada com sucesso!");
    registrarLog("Usuário " + usuario.login + " alterou sua senha.");

}

public static void menuUsuario(Usuario usuarioLogado) {
    int opcao = -1;

    do {
        System.out.println("\n**** MENU USUÁRIO ****");
        System.out.println("1 - Enviar mensagem");
        System.out.println("2 - Ver mensagens recebidas");
        System.out.println("3 - Alterar senha");
        System.out.println("4 - Logout");
        System.out.println("5 - conversões númericas");
        System.out.print("Escolha uma opção: ");

        try {
            opcao = Integer.parseInt(entrada.nextLine());
        } catch (NumberFormatException e) {
            System.out.println("Opção inválida! Digite um número.");
            continue;
        }

        switch (opcao) {
            case 1:
                enviarMensagem(usuarioLogado.login);
                break;
            case 2:
                verMensagensRecebidas(usuarioLogado);
                break;
            case 3:
                alterarSenha(usuarioLogado);
                break;
            case 4:
                System.out.println("Logout realizado. Voltando ao menu principal...");
                registrarLog("Usuário " + usuarioLogado.login + " fez logout.");
                break;
            case 5:
                menuConversoes();
                break;
            default:
                System.out.println("Opção inválida, tente novamente.");
        }

    } while (opcao != 5);
}

public static void desbloquearUsuario() {
    System.out.println("\n===== DESBLOQUEAR USUÁRIO =====");
    boolean temBloqueado = false;

    // lista apenas bloqueados
    for (Usuario u : usuarios) {
        if (u.bloqueado) {
            System.out.println("- " + u.login + " (" + u.nome + ")");
            temBloqueado = true;
        }
    }

    if (!temBloqueado) {
        System.out.println("Nenhum usuário bloqueado no momento.");
        return;
    }

    System.out.print("\nDigite o login do usuário que deseja desbloquear: ");
    String login = entrada.nextLine();

    for (Usuario u : usuarios) {
        if (u.login.equals(login)) {
            if (u.bloqueado) {
                u.bloqueado = false;
                u.tentativasErradas = 0;
                System.out.println("Usuário " + u.login + " foi desbloqueado com sucesso!");
                registrarLog("Admin desbloqueou o usuário " + u.login);
                return;
            } else {
                System.out.println("Esse usuário não está bloqueado.");
                return;
            }
        }
    }

    System.out.println("Usuário não encontrado.");
}

public static void menuConversoes() {
    Scanner sc = new Scanner(System.in);
    int opcao;

    do {
        System.out.println("*****CONVERSOR NÚMERICO*****");
        System.out.println("1 - decimal para binario");
        System.out.println("2 - binario para decimal");
        System.out.println("3 - decimal para octal");
        System.out.println("4 - decimal para hexadecimal");
        System.out.println("5 - operações logicas (and, or, not)");
        System.out.println("0 - voltar");
        System.out.println("Escolha uma opção");
        opcao = sc.nextInt();
        sc.nextLine();

        switch (opcao) {
            case 1:
                decimalParaBinario(sc);
                break;
            case 2:
                binarioParaDecimal(sc);
                break;
            case 3:
                decimalParaOctal(sc);
                break;
            case 4:
                decimalHexadecimal(sc);
                break;
            case 5:
                operacoesLogicas(sc);
                break;
            case 0:
                System.out.println("voltando...");
                menuUsuario(null);
                break;
            default:
                System.out.println("opção invalida");
                break;
        }
    } while (opcao != 0);
}

public static void decimalParaBinario(Scanner sc) {
    System.out.print("Digite um número decimal: ");
    int decimal = sc.nextInt();

    if (decimal == 0) {
        System.out.println("0 em binário é 0");
        return;
    }

    StringBuilder passos = new StringBuilder();
    int numero = decimal;
    StringBuilder binario = new StringBuilder();

    while (numero > 0) {
        int resto = numero % 2;
        passos.append(numero + " / 2 = " + (numero / 2) + " resto " + resto + "\n");
        binario.insert(0, resto); // insere no início
        numero /= 2;
    }

    System.out.println("\n--- Passo a passo ---");
    System.out.println(passos.toString());
    System.out.println(decimal + " em binário é: " + binario.toString());
}

public static void binarioParaDecimal(Scanner sc) {
    System.out.print("Digite um número binário: ");
    String binario = sc.nextLine();

    int decimal = 0;
    int potencia = 0;
    StringBuilder passos = new StringBuilder();

    for (int i = binario.length() - 1; i >= 0; i--) {
        char digito = binario.charAt(i);
        if (digito != '0' && digito != '1') {
            System.out.println("Erro: o número digitado não é binário!");
            return;
        }

        int valor = Character.getNumericValue(digito);
        int resultado = valor * (int) Math.pow(2, potencia);

        passos.append(digito + " × 2^" + potencia + " = " + resultado + "\n");

        decimal += resultado;
        potencia++;
    }

    System.out.println("\n--- Passo a passo ---");
    System.out.println(passos.toString());
    System.out.println(binario + " em decimal é: " + decimal);
}

public static void decimalParaOctal(Scanner sc) {
    System.out.print("Digite um número decimal: ");
    int decimal = sc.nextInt();

    if (decimal == 0) {
        System.out.println("0 em octal é 0");
        return;
    }

    StringBuilder passos = new StringBuilder();
    int numero = decimal;
    StringBuilder octal = new StringBuilder();

    while (numero > 0) {
        int resto = numero % 8;
        passos.append(numero + " / 8 = " + (numero / 8) + " resto " + resto + "\n");
        octal.insert(0, resto); // insere o dígito na frente
        numero /= 8;
    }

    System.out.println("\n--- Passo a passo ---");
    System.out.println(passos.toString());
    System.out.println(decimal + " em octal é: " + octal.toString());
}

public static void decimalHexadecimal(Scanner sc) {
    System.out.print("Digite um número decimal: ");
    int decimal = sc.nextInt();

    if (decimal == 0) {
        System.out.println("0 em hexadecimal é 0");
        return;
    }

    StringBuilder passos = new StringBuilder();
    int numero = decimal;
    StringBuilder hexadecimal = new StringBuilder();

    // tabela pra converter valores de 10 a 15 em letras
    char[] hexDigitos = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    while (numero > 0) {
        int resto = numero % 16;
        passos.append(numero + " / 16 = " + (numero / 16) + " resto " + resto + " (" + hexDigitos[resto] + ")\n");
        hexadecimal.insert(0, hexDigitos[resto]);
        numero /= 16;
    }

    System.out.println("\n--- Passo a passo ---");
    System.out.println(passos.toString());
    System.out.println(decimal + " em hexadecimal é: " + hexadecimal.toString());
}

public static void operacoesLogicas(Scanner sc) {
    System.out.println("Escolha a operação lógica:");
    System.out.println("1 - AND");
    System.out.println("2 - OR");
    System.out.println("3 - NOT");
    int opcao = sc.nextInt();
    sc.nextLine();

    switch (opcao) {
        case 1:
            System.out.print("Digite o primeiro número binário: ");
            String bin1 = sc.nextLine();
            System.out.print("Digite o segundo número binário: ");
            String bin2 = sc.nextLine();
            System.out.println("Resultado AND: " + andBinario(bin1, bin2));
            break;
        case 2:
            System.out.print("Digite o primeiro número binário: ");
            bin1 = sc.nextLine();
            System.out.print("Digite o segundo número binário: ");
            bin2 = sc.nextLine();
            System.out.println("Resultado OR: " + orBinario(bin1, bin2));
            break;
        case 3:
            System.out.print("Digite um número binário: ");
            bin1 = sc.nextLine();
            System.out.println("Resultado NOT: " + notBinario(bin1));
            break;
        default:
            System.out.println("Opção inválida!");
    }
}

// Métodos auxiliares para operações lógicas
public static String andBinario(String a, String b) {
    int maxLen = Math.max(a.length(), b.length());
    a = String.format("%" + maxLen + "s", a).replace(' ', '0');
    b = String.format("%" + maxLen + "s", b).replace(' ', '0');
    StringBuilder resultado = new StringBuilder();
    for (int i = 0; i < maxLen; i++) {
        resultado.append((a.charAt(i) == '1' && b.charAt(i) == '1') ? '1' : '0');
    }
    return resultado.toString();
}

public static String orBinario(String a, String b) {
    int maxLen = Math.max(a.length(), b.length());
    a = String.format("%" + maxLen + "s", a).replace(' ', '0');
    b = String.format("%" + maxLen + "s", b).replace(' ', '0');
    StringBuilder resultado = new StringBuilder();
    for (int i = 0; i < maxLen; i++) {
        resultado.append((a.charAt(i) == '1' || b.charAt(i) == '1') ? '1' : '0');
    }
    return resultado.toString();
}

public static String notBinario(String a) {
    StringBuilder resultado = new StringBuilder();
    for (int i = 0; i < a.length(); i++) {
        resultado.append(a.charAt(i) == '1' ? '0' : '1');
    }
    return resultado.toString();
}

}


******************************************************************

Usuario.java

import java.util.ArrayList;

public class Usuario {
    String nome;
    String login;
    String senha;
    boolean bloqueado;
    int tentativasErradas;
    ArrayList<String> mensagens;

    public Usuario(String nome, String login, String senha) {
        this.nome = nome;
        this.login = login;
        this.senha = senha;
        this.bloqueado = false;
        this.tentativasErradas = 0;
        this.mensagens = new ArrayList<>();
    }

    @Override
    public String toString() {
        String status = bloqueado ? " (BLOQUEADO)" : "";
        return "Usuário: " + nome + " (" + login + ")" + status;
    }
}

********************************************************************

codigo.simulador

import java.util.*;

class Processo {
    String nome;            
    int tempoExecucao;      
    int prioridade;        


    Processo(String nome, int tempoExecucao, int prioridade) {
        this.nome = nome;
        this.tempoExecucao = tempoExecucao;
        this.prioridade = prioridade;
    }
}

public class SimuladorDeProcessos {

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in); 
        List<Processo> processos = new ArrayList<>(); 

        System.out.println("Simulador de Processos");
        System.out.print("Quantos processos deseja criar? ");
        int qtd = sc.nextInt();

        for (int i = 0; i < qtd; i++) {
            System.out.println("\n Processo " + (i + 1) + " ");
            System.out.print("Nome do processo: ");
            String nome = sc.next();

            System.out.print("Tempo de execução (em segundos): ");
            int tempo = sc.nextInt();

            System.out.print("Prioridade (quanto menor, mais prioridade): ");
            int prioridade = sc.nextInt();

            processos.add(new Processo(nome, tempo, prioridade));
        }

        System.out.println("\nEscolha o tipo de escalonamento:");
        System.out.println("1 - FCFS (Primeiro a Chegar, Primeiro a Ser Atendido)");
        System.out.println("2 - Round Robin (Dividido por tempo)");
        System.out.println("3 - Prioridade (Mais importante primeiro)");
        System.out.print("Digite sua opção: ");
        int opcao = sc.nextInt();

        switch (opcao) {
            case 1 -> fcfs(processos);
            case 2 -> roundRobin(processos, sc);
            case 3 -> prioridade(processos);
            default -> System.out.println("Opção inválida!");
        }

        System.out.println("\nSimulação finalizada.");
        sc.close();
    }

    static void fcfs(List<Processo> processos) {
        System.out.println("\n Escalonamento FCFS ");
        System.out.println("(O primeiro processo que chega é o primeiro a ser executado.)");

        for (Processo p : processos) {
            System.out.println("\nExecutando processo: " + p.nome);
            esperar(p.tempoExecucao);
            System.out.println("Processo " + p.nome + " finalizado!");
        }
    }

    static void roundRobin(List<Processo> processos, Scanner sc) {
        System.out.print("\nDigite o valor do quantum (tempo máximo por processo): ");
        int quantum = sc.nextInt();

        System.out.println("\n Escalonamento Round Robin ");
        System.out.println("(Cada processo executa por um tempo fixo e depois dá chance ao próximo.)");

        Queue<Processo> fila = new LinkedList<>(processos);

        while (!fila.isEmpty()) {
            Processo p = fila.poll(); 
            int tempoRestante = p.tempoExecucao - quantum;

            System.out.println("\nExecutando " + p.nome + " por " + quantum + "s");
            esperar(quantum);

            if (tempoRestante > 0) {
                p.tempoExecucao = tempoRestante; 
                fila.add(p); 
                System.out.println(p.nome + " ainda não terminou, voltará à fila (restam " + tempoRestante + "s)");
            } else {
                System.out.println(p.nome + " finalizado!");
            }
        }
    }

    static void prioridade(List<Processo> processos) {
        System.out.println("\n Escalonamento por Prioridade ");
        System.out.println("(Os processos com menor número de prioridade executam primeiro.)");

        processos.sort(Comparator.comparingInt(p -> p.prioridade));

        for (Processo p : processos) {
            System.out.println("\nExecutando processo (prioridade " + p.prioridade + "): " + p.nome);
            esperar(p.tempoExecucao);
            System.out.println("Processo " + p.nome + " finalizado!");
        }
    }

    
    static void esperar(int tempo) {
        try {
            Thread.sleep(tempo * 1000); 
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }


    **************************************************************



    import java.util.*;

class Processo {
    String nome;            
    int tempoExecucao;      
    int prioridade;        


    Processo(String nome, int tempoExecucao, int prioridade) {
        this.nome = nome;
        this.tempoExecucao = tempoExecucao;
        this.prioridade = prioridade;
    }
}

public class SimuladorDeProcessos {

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in); 
        List<Processo> processos = new ArrayList<>(); 

        System.out.println("Simulador de Processos");
        System.out.print("Quantos processos deseja criar? ");
        int qtd = sc.nextInt();

        for (int i = 0; i < qtd; i++) {
            System.out.println("\n Processo " + (i + 1) + " ");
            System.out.print("Nome do processo: ");
            String nome = sc.next();

            System.out.print("Tempo de execução (em segundos): ");
            int tempo = sc.nextInt();

            System.out.print("Prioridade (quanto menor, mais prioridade): ");
            int prioridade = sc.nextInt();

            processos.add(new Processo(nome, tempo, prioridade));
        }

        System.out.println("\nEscolha o tipo de escalonamento:");
        System.out.println("1 - FCFS (Primeiro a Chegar, Primeiro a Ser Atendido)");
        System.out.println("2 - Round Robin (Dividido por tempo)");
        System.out.println("3 - Prioridade (Mais importante primeiro)");
        System.out.print("Digite sua opção: ");
        int opcao = sc.nextInt();

        switch (opcao) {
            case 1 -> fcfs(processos);
            case 2 -> roundRobin(processos, sc);
            case 3 -> prioridade(processos);
            default -> System.out.println("Opção inválida!");
        }

        System.out.println("\nSimulação finalizada.");
        sc.close();
    }

    static void fcfs(List<Processo> processos) {
        System.out.println("\n Escalonamento FCFS ");
        System.out.println("(O primeiro processo que chega é o primeiro a ser executado.)");

        for (Processo p : processos) {
            System.out.println("\nExecutando processo: " + p.nome);
            esperar(p.tempoExecucao);
            System.out.println("Processo " + p.nome + " finalizado!");
        }
    }

    static void roundRobin(List<Processo> processos, Scanner sc) {
        System.out.print("\nDigite o valor do quantum (tempo máximo por processo): ");
        int quantum = sc.nextInt();

        System.out.println("\n Escalonamento Round Robin ");
        System.out.println("(Cada processo executa por um tempo fixo e depois dá chance ao próximo.)");

        Queue<Processo> fila = new LinkedList<>(processos);

        while (!fila.isEmpty()) {
            Processo p = fila.poll(); 
            int tempoRestante = p.tempoExecucao - quantum;

            System.out.println("\nExecutando " + p.nome + " por " + quantum + "s");
            esperar(quantum);

            if (tempoRestante > 0) {
                p.tempoExecucao = tempoRestante; 
                fila.add(p); 
                System.out.println(p.nome + " ainda não terminou, voltará à fila (restam " + tempoRestante + "s)");
            } else {
                System.out.println(p.nome + " finalizado!");
            }
        }
    }

    static void prioridade(List<Processo> processos) {
        System.out.println("\n Escalonamento por Prioridade ");
        System.out.println("(Os processos com menor número de prioridade executam primeiro.)");

        processos.sort(Comparator.comparingInt(p -> p.prioridade));

        for (Processo p : processos) {
            System.out.println("\nExecutando processo (prioridade " + p.prioridade + "): " + p.nome);
            esperar(p.tempoExecucao);
            System.out.println("Processo " + p.nome + " finalizado!");
        }
    }

    
    static void esperar(int tempo) {
        try {
            Thread.sleep(tempo * 1000); 
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    **********************************************************






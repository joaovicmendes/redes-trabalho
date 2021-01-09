class CamadaEnlace:
    ignore_checksum = False

    def __init__(self, linhas_seriais):
        """
        Inicia uma camada de enlace com um ou mais enlaces, cada um conectado
        a uma linha serial distinta. O argumento linhas_seriais é um dicionário
        no formato {ip_outra_ponta: linha_serial}. O ip_outra_ponta é o IP do
        host ou roteador que se encontra na outra ponta do enlace, escrito como
        uma string no formato 'x.y.z.w'. A linha_serial é um objeto da classe
        PTY (vide camadafisica.py) ou de outra classe que implemente os métodos
        registrar_recebedor e enviar.
        """
        self.enlaces = {}
        self.callback = None
        # Constrói um Enlace para cada linha serial
        for ip_outra_ponta, linha_serial in linhas_seriais.items():
            enlace = Enlace(linha_serial)
            self.enlaces[ip_outra_ponta] = enlace
            enlace.registrar_recebedor(self._callback)

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de enlace
        """
        self.callback = callback

    def enviar(self, datagrama, next_hop):
        """
        Envia datagrama para next_hop, onde next_hop é um endereço IPv4
        fornecido como string (no formato x.y.z.w). A camada de enlace se
        responsabilizará por encontrar em qual enlace se encontra o next_hop.
        """
        # Encontra o Enlace capaz de alcançar next_hop e envia por ele
        self.enlaces[next_hop].enviar(datagrama)

    def _callback(self, datagrama):
        if self.callback:
            self.callback(datagrama)


class Enlace:
    def __init__(self, linha_serial):
        self.linha_serial = linha_serial
        self.linha_serial.registrar_recebedor(self.__raw_recv)
        self.dados_residuais = ""

    def registrar_recebedor(self, callback):
        self.callback = callback

    def enviar(self, datagrama):
        datagrama_escaped = b''

        # Escapando bytes '0xc0' e '0xdb'
        for byte in list(datagrama):
            if byte == 0xc0:
                datagrama_escaped = datagrama_escaped + bytes([0xdb, 0xdc])
            elif byte == 0xdb:
                datagrama_escaped = datagrama_escaped + bytes([0xdb, 0xdd])
            else:
                datagrama_escaped = datagrama_escaped + bytes([byte])

        dados = bytes([0xc0]) + datagrama_escaped + bytes([0xc0])
        self.linha_serial.enviar(dados)

    def __raw_recv(self, dados):
        # Caso parte do comando tenha vindo antes
        self.dados_residuais = self.dados_residuais + dados.hex()

        # Enquanto tiver um comando completo nos dados residuais
        while self.dados_residuais.find("c0") != -1:
            # Recortando o primeiro comando completo existente
            payload, _, self.dados_residuais = self.dados_residuais.partition("c0")

            # Ignorando payload vazio
            if payload == "":
                continue
            else:
                self.callback(bytes.fromhex(payload))

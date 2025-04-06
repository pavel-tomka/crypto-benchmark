from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import os
import timeit
import random
import math
from tabulate import tabulate

TEST_DATA_SIZE = 1 * 1024 * 1024  # 1 MB
ITERATIONS = 5
DATA = os.urandom(TEST_DATA_SIZE)

def test_aes():
    """Тест AES-256-GCM"""

    def aes_encrypt(key, data):
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return ciphertext, encryptor.tag, nonce

    def aes_decrypt(key, ciphertext, tag, nonce):
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    results = {}

    key_gen_time = timeit.timeit(
        lambda: os.urandom(32),
        number=ITERATIONS
    ) / ITERATIONS

    key = os.urandom(32)

    encrypt_time = timeit.timeit(
        lambda: aes_encrypt(key, DATA),
        number=ITERATIONS
    ) / ITERATIONS

    ciphertext, tag, nonce = aes_encrypt(key, DATA)
    decrypt_time = timeit.timeit(
        lambda: aes_decrypt(key, ciphertext, tag, nonce),
        number=ITERATIONS
    ) / ITERATIONS

    results.update({
        "Тип": "Симметричный",
        "Размер ключа": "256 бит",
        "Генерация ключа": f"{key_gen_time * 1000:.2f} мс",
        "Шифрование": f"{encrypt_time * 1000:.2f} мс",
        "Дешифрование": f"{decrypt_time * 1000:.2f} мс",
        "Нагрузка": f"{len(ciphertext) / 1024:.1f} KB"
    })
    return results

def test_rsa_native():
    """Тест нативного RSA-2048"""

    def is_prime(n, k=5):
        """Проверка числа на простоту с использованием теста Миллера-Рабина"""
        if n <= 1 or n == 4:
            return False
        if n <= 3:
            return True

        # Находим r и d такие, что n-1 = 2^r * d, где d нечетное
        d = n - 1
        r = 0
        while d % 2 == 0:
            d //= 2
            r += 1

        # Проводим k тестов
        for _ in range(k):
            if not miller_rabin_test(n, d, r):
                return False
        return True

    def miller_rabin_test(n, d, r):
        """Один раунд теста Миллера-Рабина"""
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            return True

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                return True

        return False

    def gcd(a, b):
        """Наибольший общий делитель с использованием алгоритма Евклида"""
        while b:
            a, b = b, a % b
        return a

    def mod_inverse(e, phi):
        """Нахождение мультипликативного обратного по модулю с использованием расширенного алгоритма Евклида"""

        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            else:
                gcd, x, y = extended_gcd(b % a, a)
                return gcd, y - (b // a) * x, x

        g, x, y = extended_gcd(e, phi)
        if g != 1:
            raise Exception('Модульная инверсия не существует')
        else:
            return x % phi

    def generate_prime(bits):
        """Генерирует простое число заданного размера в битах"""
        while True:
            # Генерируем случайное нечетное число
            p = random.getrandbits(bits) | (1 << bits - 1) | 1
            if is_prime(p):
                return p

    def generate_rsa_keys(bits=2048):
        """Генерирует пару ключей RSA с заданным размером в битах"""
        # Для реальной генерации RSA ключей, p и q должны быть примерно одинаковой длины
        p_bits = bits // 2
        q_bits = bits - p_bits

        p = generate_prime(p_bits)
        q = generate_prime(q_bits)

        n = p * q
        phi = (p - 1) * (q - 1)

        # Выбираем e так, чтобы e и phi были взаимно простыми
        e = 65537  # Обычно используется число 65537
        while gcd(e, phi) != 1:
            e = random.randrange(2, phi)

        # Вычисляем d, мультипликативное обратное для e mod phi
        d = mod_inverse(e, phi)

        return ((e, n), (d, n))

    def rsa_encrypt_native(public_key, data):
        """Шифрует данные с использованием нативной реализации RSA"""
        e, n = public_key
        # Работаем с данными как с байтами
        result = bytearray()

        # Размер блока для шифрования (в байтах) для избежания переполнения
        # Ключ RSA 2048 бит = 256 байт, сохраняем запас для padding
        block_size = (math.log(n, 256)) - 1
        block_size = int(block_size)

        # Разбиваем данные на блоки и шифруем каждый блок
        for i in range(0, len(data), block_size):
            block = data[i:i + block_size]
            # Преобразуем блок в большое целое число
            m = int.from_bytes(block, byteorder='big')
            # Шифруем: c = m^e mod n
            c = pow(m, e, n)
            # Преобразуем шифртекст обратно в байты с постоянной длиной
            c_bytes = c.to_bytes((c.bit_length() + 7) // 8, byteorder='big')
            # Добавляем информацию о длине для возможности корректной расшифровки
            length_bytes = len(c_bytes).to_bytes(2, byteorder='big')
            result.extend(length_bytes + c_bytes)

        return bytes(result)

    def rsa_decrypt_native(private_key, data):
        """Дешифрует данные с использованием нативной реализации RSA"""
        d, n = private_key
        result = bytearray()
        i = 0

        # Читаем блоки данных
        while i < len(data):
            # Читаем длину текущего блока
            length = int.from_bytes(data[i:i + 2], byteorder='big')
            i += 2
            # Получаем шифртекст текущего блока
            c_bytes = data[i:i + length]
            i += length
            # Преобразуем в целое число
            c = int.from_bytes(c_bytes, byteorder='big')
            # Дешифруем: m = c^d mod n
            m = pow(c, d, n)
            # Определяем минимальное количество байт для представления расшифрованного числа
            byte_length = (m.bit_length() + 7) // 8
            # Преобразуем обратно в байты
            m_bytes = m.to_bytes(byte_length, byteorder='big')
            result.extend(m_bytes)

        return bytes(result)

    results = {}

    key_gen_time = timeit.timeit(
        lambda: generate_rsa_keys(2048),
        number=1  # Используем только одну итерацию для генерации ключей, т.к. это долгая операция
    )

    # Масштабируем для среднего значения
    key_gen_time = key_gen_time / 1

    public_key, private_key = generate_rsa_keys(2048)

    # Используем только часть данных для тестирования, чтобы ускорить процесс
    test_data = DATA[:10000]  # Берем первые 10KB данных

    encrypt_time = timeit.timeit(
        lambda: rsa_encrypt_native(public_key, test_data),
        number=ITERATIONS
    ) / ITERATIONS

    # Масштабируем результат для полного размера данных
    encrypt_time = encrypt_time * (len(DATA) / len(test_data))

    ciphertext = rsa_encrypt_native(public_key, test_data)
    decrypt_time = timeit.timeit(
        lambda: rsa_decrypt_native(private_key, ciphertext),
        number=ITERATIONS
    ) / ITERATIONS

    # Масштабируем результат для полного размера данных
    decrypt_time = decrypt_time * (len(DATA) / len(test_data))

    # Оцениваем размер шифртекста для полного размера данных
    estimated_ciphertext_size = len(ciphertext) * (len(DATA) / len(test_data))

    results.update({
        "Тип": "Асимметричный",
        "Размер ключа": "2048 бит",
        "Генерация ключа": f"{key_gen_time * 1000:.2f} мс",
        "Шифрование": f"{encrypt_time * 1000:.2f} мс",
        "Дешифрование": f"{decrypt_time * 1000:.2f} мс",
        "Нагрузка": f"{estimated_ciphertext_size / 1024:.1f} KB"
    })
    return results

def test_pure_ecc():
    """Тест чистого ECC-256"""

    def pure_ecc_encrypt(public_key, data):
        """Функция для реализации непосредственного шифрования данных с помощью ECC"""
        # Поскольку cryptography не предоставляет прямой метод шифрования ECC,
        # мы реализуем ECIES (Elliptic Curve Integrated Encryption Scheme)

        # Генерируем временную пару ключей
        temp_private = ec.generate_private_key(public_key.curve, default_backend())
        temp_public = temp_private.public_key()

        # Обмен ключами
        shared_secret = temp_private.exchange(ec.ECDH(), public_key)

        # Получаем ключ для симметричного шифрования из общего секрета
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ecies-encryption',
            backend=default_backend()
        )
        key = hkdf.derive(shared_secret)

        # Шифруем данные с помощью ключа
        # В реальном ECIES используется симметричное шифрование, но здесь мы просто
        # используем XOR для простоты, чтобы продемонстрировать принцип
        ciphertext = bytes(a ^ b for a, b in zip(data, key[:len(data)]))

        # Сохраняем публичный ключ для дешифрования
        pub_bytes = temp_public.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

        return pub_bytes + ciphertext

    def pure_ecc_decrypt(private_key, ciphertext):
        """Функция для дешифрования данных, зашифрованных с использованием ECC"""
        # Получаем длину публичного ключа
        sample_pub = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        pub_len = len(sample_pub)

        # Извлекаем публичный ключ отправителя и сам шифртекст
        pub_key_bytes = ciphertext[:pub_len]
        encrypted = ciphertext[pub_len:]

        # Восстанавливаем публичный ключ отправителя
        temp_public = ec.EllipticCurvePublicKey.from_encoded_point(
            private_key.curve,
            pub_key_bytes
        )

        # Обмен ключами
        shared_secret = private_key.exchange(ec.ECDH(), temp_public)

        # Получаем ключ для симметричного шифрования из общего секрета
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ecies-encryption',
            backend=default_backend()
        )
        key = hkdf.derive(shared_secret)

        # Дешифруем данные с помощью ключа (используем XOR)
        plaintext = bytes(a ^ b for a, b in zip(encrypted, key[:len(encrypted)]))

        return plaintext

    results = {}

    curve = ec.SECP256R1()  # Используем кривую P-256 для лучшего сравнения (256 бит)
    key_gen_time = timeit.timeit(
        lambda: ec.generate_private_key(curve, default_backend()),
        number=ITERATIONS
    ) / ITERATIONS

    private_key = ec.generate_private_key(curve, default_backend())
    public_key = private_key.public_key()

    # Для чистого ECC, данные должны быть разбиты на части, поскольку ECC может шифровать
    # только ограниченный объем данных непосредственно
    # Для SECP256R1 максимальный размер данных будет примерно 32 байта (256 бит)
    chunk_size = 32
    chunks = [DATA[i:i + chunk_size] for i in range(0, len(DATA), chunk_size)]

    encrypt_time = timeit.timeit(
        lambda: [pure_ecc_encrypt(public_key, chunk) for chunk in
                 chunks[:100]],  # Берем первые 100 чанков для ускорения
        number=ITERATIONS
    ) / ITERATIONS

    # Масштабируем результат на полный объем данных
    encrypt_time = encrypt_time * (len(chunks) / 100)

    ciphertext = [pure_ecc_encrypt(public_key, chunk) for chunk in chunks[:100]]
    decrypt_time = timeit.timeit(
        lambda: [pure_ecc_decrypt(private_key, c) for c in ciphertext],
        number=ITERATIONS
    ) / ITERATIONS

    # Масштабируем результат на полный объем данных
    decrypt_time = decrypt_time * (len(chunks) / 100)

    # Оцениваем общий размер шифртекста для всех фрагментов
    estimated_ciphertext_size = (sum(len(c) for c in ciphertext) / len(ciphertext)) * len(chunks)

    results.update({
        "Тип": "Асимметричный",
        "Размер ключа": "256 бит",
        "Генерация ключа": f"{key_gen_time * 1000:.2f} мс",
        "Шифрование": f"{encrypt_time * 1000:.2f} мс",
        "Дешифрование": f"{decrypt_time * 1000:.2f} мс",
        "Нагрузка": f"{estimated_ciphertext_size / 1024:.1f} KB"
    })
    return results


if __name__ == "__main__":
    print(f"Тестирование на {TEST_DATA_SIZE / 1024 / 1024:.1f} MB данных...")

    tests = {
        "AES": test_aes(),
        "RSA (native)": test_rsa_native(),
        "ECC (native)": test_pure_ecc()
    }

    headers = ["Алгоритм", "Тип", "Размер ключа", "Генерация ключа",
               "Шифрование", "Дешифрование", "Нагрузка"]

    table = [[k] + [v[h] for h in headers[1:]] for k, v in tests.items()]

    print("\nРезультаты тестирования:")
    print(tabulate(table, headers=headers, tablefmt="grid", stralign="center"))

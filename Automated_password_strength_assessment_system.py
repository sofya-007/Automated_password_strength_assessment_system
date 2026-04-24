# Подключаемые библиотеки:

import re         # регулярные выражения (для поиска повторяющихся символов)
import math       # математические функции (log2 для расчёта энтропии, обработка переполнения)
import csv        # работа с CSV-файлами (генерация памятки с рекомендациями)
import argparse   # разбор аргументов командной строки (флаги --recommendations, --output)
import sys        # доступ к системным функциям (обработка исключений, завершение программы)
from typing import List, Tuple # аннотации типов (List, Tuple для улучшения читаемости кода)

class PasswordAnalyzer:
    """
    Класс для анализа стойкости паролей к брутфорс‑атакам.
    Содержит методы расчёта энтропии, времени взлома,
    проверки на словарные атаки, гибридные атаки и типовые уязвимости.
    """

    def __init__(self):
        """
        Внутренние данные: сценарии скорости перебора,
        список распространённых паролей, карта leetspeak‑замен,
        список типовых последовательностей.
        """
        # Словарь сценариев скорости перебора для различных вычислительных систем.
        
        self.speed_scenarios = {
            "Домашняя система (CPU)": 10 ** 5, # Обычный домашний компьютер
            "Мощный ПК (GPU)": 10 ** 7,        # Мощный игровой ПК с видеокартой
            "Кластер/ASIC": 10 ** 10           # Высокопроизводительный кластер или специализированное оборудование
        }

        # Список самых распространённых паролей (словарь для атаки по словарю).
        self.common_passwords = [
            'password', 'pass', '123456', '123456789', 'qwerty', 'abc123',
            'football', 'monkey', 'letmein', 'login', 'admin', 'welcome',
            'shadow', 'sunshine', 'princess', 'dragon', 'master', 'hello',
            'freedom', 'whatever', 'qazwsx', 'trustno1', '654321',
            'iloveyou', 'secret', 'superman', 'batman', 'spider', 'google',
            'yahoo', 'microsoft', 'apple', 'samsung', 'android', 'iphone',
            'samsung123', 'password1', 'mypassword', 'myname', 'mylogin',
            'user', 'guest', 'test', 'demo', 'sample', 'example',
            'access', 'secure', 'safe', 'private', 'confidential', 'topsecret',
            'hackme', 'nopass', 'nopassword', 'easy', 'simple', 'weak'
        ]

        # Словарь замен символов на визуально похожие (для обнаружения leetspeak‑модификаций).
        self.leetspeak_map = {
            'a': '@', 'A': '@',
            's': '$', 'S': '$',
            'o': '0', 'O': '0',
            'i': '1', 'I': '1',
            'e': '3', 'E': '3',
            't': '7', 'T': '7',
            'l': '1', 'L': '1',
            'z': '2', 'Z': '2',
            'b': '6', 'B': '6'
        }

        # Список распространённых буквенных, цифровых и клавиатурных последовательностей.
        self.sequences = [
            '123', '234', '345', '456', '567', '678', '789', '890', '098', '987', '876', '765', '654',
            '543', '432', '321', '210', '111', '222', '333', '444', '555', '666', '777', '888', '999',
            'abc', 'bcd', 'cde', 'def', 'efg', 'fgh', 'ghi', 'hij', 'ijk', 'jkl', 'klm', 'lmn',
            'mno', 'nop', 'opq', 'pqr', 'qrs', 'rst', 'stu', 'tuv', 'uvw', 'vwx', 'wxy', 'xyz', 'zyx',
            'yxw', 'xwv', 'wvu', 'vut', 'uts', 'tsr', 'srq', 'rqp', 'qpo', 'pon', 'onm',
            'nml', 'mlk', 'lkj', 'kji', 'jih', 'ihg', 'hgf', 'gfe', 'fed', 'edc', 'dcb', 'cba',
            'qwe', 'wer', 'ert', 'rty', 'tyu', 'yui', 'uio', 'iop', 'asd', 'sdf', 'dfg', 'fgh',
            'ghj', 'hjk', 'jkl', 'zxc', 'xcv', 'cvb', 'vbn', 'bnm'
        ]

    def get_charset_size(self, password: str) -> int:
        """
        Определяет мощность алфавита (количество возможных символов) для данного пароля.
        Учитываются только латинские буквы, цифры и специальные символы.
        Кириллица игнорируется (не добавляется в мощность).
        Возвращает сумму размеров присутствующих классов/
        """
        has_lower = any(c.islower() and 'a' <= c <= 'z' for c in password) # строчные латинские: 26
        has_upper = any(c.isupper() and 'A' <= c <= 'Z' for c in password) # прописные латинские: 26
        has_digits = any(c.isdigit() for c in password)                    # цифры: 10
        has_special = any(not c.isalnum() for c in password)               # спецсимволы: 32

        size = 0
        if has_lower:
            size += 26
        if has_upper:
            size += 26
        if has_digits:
            size += 10
        if has_special:
            size += 32
        return size

    def calculate_keyspace(self, length: int, charset_size: int) -> float:
        """
        Вычисляет пространство ключей (общее количество возможных комбинаций)
        по формуле N^L. При переполнении возвращает float('inf').
        """
        try:
            return charset_size ** length
        except OverflowError:
            return float('inf')

    def estimate_crack_time(self, keyspace: float, speed: int) -> float:
        """
        Оценивает среднее время полного перебора (в секундах).
        Формула: T = keyspace / (2 * speed).
        Если keyspace бесконечен, возвращает бесконечность.
        Деление на 2 – потому что в среднем перебирается половина пространства.
        """
        if keyspace == float('inf'):
            return float('inf')
        return keyspace / (2 * speed)

    def _generate_all_leetspeak_combinations(self, word: str) -> List[str]:
        """
        Рекурсивно генерирует все возможные варианты leetspeak‑замен для заданного слова.
        Вход: строка.
        Выход: список строк со всеми комбинациями замен.
        """
        if not word:
            return ['']
        first_char = word[0]
        rest = word[1:]
        if first_char in self.leetspeak_map:
            base_options = [first_char, self.leetspeak_map[first_char]]
        else:
            base_options = [first_char]
        rest_combinations = self._generate_all_leetspeak_combinations(rest)
        result = []
        for base in base_options:
            for suffix in rest_combinations:
                result.append(base + suffix)
        return result

    def check_dictionary_attack(self, password: str) -> List[str]:
        """
        Проверяет, находится ли пароль (в нижнем регистре) в списке распространённых паролей.
        Возвращает список с сообщением об уязвимости или пустой список.
        """
        if password.lower() in self.common_passwords:
            return ["Пароль найден в словаре распространённых паролей"]
        return []

    def check_hybrid_attack(self, password: str) -> List[str]:
        """
        Проверяет пароль на гибридные атаки:
        - leetspeak‑модификация словарного слова (например, p@ssw0rd вместо password);
        - словарное слово с leetspeak‑заменами + цифровой/символьный суффикс.
        Возвращает список обнаруженных проблем.
        """
        issues = []
        pwd_lower = password.lower()
        for word in self.common_passwords:
            if len(word) < 3:
                continue
            leetspeak_combinations = self._generate_all_leetspeak_combinations(word)
            for variant in leetspeak_combinations:
                if variant == pwd_lower:
                    issues.append(f"Гибридная атака: leetspeak‑модификация словарного слова '{word}' → '{variant}'")
                    continue
                if pwd_lower.startswith(variant):
                    suffix = pwd_lower[len(variant):]
                    if suffix and (suffix.isdigit() or suffix in ['!', '@', '#', '$', '%', '&', '*', '+', '=', '-']):
                        issues.append(
                            f"Гибридная атака: leetspeak‑модификация '{word}' + суффикс '{suffix}' "
                            f"(базовый вариант: '{variant}')"
                        )
        return issues

    def check_weak_patterns(self, password: str) -> Tuple[List[str], List[str]]:
        """
        Комплексная проверка пароля на различные уязвимости.
        Возвращает кортеж из двух списков: (список проблем, список рекомендаций).
        """
        issues = []
        suggestions = []

        # Проверка на кириллицу (недопустимые символы)
        has_cyrillic = any('а' <= c <= 'я' or 'А' <= c <= 'Я' for c in password)
        if has_cyrillic:
            issues.append("Пароль содержит кириллические символы (русские буквы). Допустимы только латинские буквы, цифры и специальные символы.")
            suggestions.append("Используйте только латинские буквы (a-z, A-Z), цифры (0-9) и специальные символы (!@#$%^&* и др.). Кириллица не поддерживается.")
            return issues, suggestions

        # Проверка длины 
        if len(password) < 10:
            issues.append("Пароль короче 10 символов")
            suggestions.append("Увеличьте длину пароля до 10+ символов — время подбора напрямую зависит от длины пароля.")

        # Проверка, что пароль состоит только из цифр
        if password.isdigit():
            issues.append("Пароль состоит только из цифр")
            suggestions.append("Добавьте буквы разного регистра и специальные символы — это увеличит мощность алфавита и усложнит подбор.")

        # Проверка, что пароль состоит только из букв (латиницы)
        if password.isalpha():
            issues.append("Пароль содержит только буквы (нет цифр и спецсимволов)")
            suggestions.append("Добавьте цифры и специальные символы — мощность алфавита напрямую влияет на стойкость пароля.")

        # Проверка на один регистр
        if password.isalpha() and (password.islower() or password.isupper()):
            issues.append("Пароль содержит буквы только одного регистра")
            suggestions.append("Используйте буквы разного регистра — это увеличивает мощность алфавита и усложняет подбор.")

        # Проверка на отсутствие специальных символов
        if not any(not c.isalnum() for c in password):
            issues.append("В пароле отсутствуют специальные символы (например, !@#$%)")
            suggestions.append("Добавьте специальные символы (например, !@#$%^&*) — это существенно увеличит мощность алфавита и усложнит подбор пароля.")

        # Проверка на наличие типовых последовательностей
        for seq in self.sequences:
            if seq in password.lower():
                issues.append(f"Обнаружена последовательность '{seq}'")
                suggestions.append(f"Избегайте типовых последовательностей вроде '{seq}' — они легко угадываются при атаках.")

        # Проверка на три и более повторяющихся символа подряд
        if re.search(r'(.)\1{2,}', password):
            issues.append("Обнаружены 3+ повторяющихся символа подряд")
            suggestions.append("Замените повторяющиеся символы на разные — это повысит сложность пароля.")

        # Проверка словарной атаки
        dict_issues = self.check_dictionary_attack(password)
        if dict_issues:
            issues.extend(dict_issues)
            suggestions.append("Полностью смените пароль — он входит в список распространённых. Используйте уникальную комбинацию, не основанную на словарных словах.")

        # Проверка гибридной атаки
        hybrid_issues = self.check_hybrid_attack(password)
        issues.extend(hybrid_issues)
        if hybrid_issues:
            suggestions.append("Полностью смените пароль — он уязвим к гибридным атакам (leetspeak + суффиксы). Избегайте модификаций словарных слов.")

        # Проверка энтропии (низкая энтропия считается уязвимостью)
        entropy = self.calculate_entropy_simple(password)
        if entropy <= 56:
            issues.append(f"Низкая энтропия ({entropy:.2f} бит) — пароль легко подбирается перебором.")
            suggestions.append("Увеличьте длину пароля и/или используйте символы разных классов (цифры, спецсимволы, разный регистр) для повышения энтропии.")

        return issues, suggestions

    def calculate_entropy_simple(self, password: str) -> float:
        """
        Рассчитывает энтропию пароля по формуле: H = L * log2(N),
        где L – длина, N – мощность алфавита.
        Энтропия выражается в битах и показывает сложность перебора.
        """
        length = len(password)
        charset_size = self.get_charset_size(password)
        if charset_size == 0:
            return 0.0
        return length * math.log2(charset_size)

    def generate_report(self, password: str) -> str:
        """
        Формирует полный текстовый отчёт по паролю:
        основные параметры (длина, мощность, пространство ключей, энтропия),
        время взлома для трёх сценариев (CPU, GPU, ASIC/кластер),
        обнаруженные уязвимости,
        персонализированные рекомендации,
        общая оценка стойкости.
        """
        has_cyrillic = any('а' <= c <= 'я' or 'А' <= c <= 'Я' for c in password)

        length = len(password)
        charset_size = self.get_charset_size(password)
        keyspace = self.calculate_keyspace(length, charset_size)
        entropy = self.calculate_entropy_simple(password)

        sec_in_year = 31557600  # количество секунд в году (365.25 дней)
        times = {}
        if has_cyrillic:
            for name in self.speed_scenarios:
                times[name] = {'seconds': float('inf'), 'years': float('inf')}
        else:
            for name, speed in self.speed_scenarios.items():
                sec = self.estimate_crack_time(keyspace, speed)
                years = sec / sec_in_year if sec != float('inf') else float('inf')
                times[name] = {'seconds': sec, 'years': years}

        issues, suggestions = self.check_weak_patterns(password)

        # Определение уровня стойкости
        if has_cyrillic:
            strength = "Не определена (недопустимые символы)"
        else:
            # Критически слабый  при словарной или гибридной атаке.
            has_critical = any(
                ("Пароль найден в словаре распространённых паролей" in issue) or
                ("Гибридная атака" in issue)
                for issue in issues
            )
            if has_critical:
                strength = "Критически слабый"
            else:
                cluster_years = times["Кластер/ASIC"]['years']
                if cluster_years < 1/365:      # менее 1 дня
                    strength = "Критически слабый"
                elif cluster_years < 1:        # менее 1 года
                    strength = "Очень слабый"
                elif cluster_years < 3:        # менее 3 лет
                    strength = "Слабый"
                elif 3 <= cluster_years <= 15: # от 3 до 15 лет
                    strength = "Средний"
                elif cluster_years < 100:      # от 15 до 100 лет
                    strength = "Стойкий"
                else:                          # 100 лет и более
                    strength = "Очень стойкий"

        # Формирование отчёта
        report = f"""
\nРЕЗУЛЬТАТЫ АНАЛИЗА ПАРОЛЯ: 

1. ОСНОВНЫЕ ПАРАМЕТРЫ ВАШЕГО ПАРОЛЯ:
    - Длина: {length} символов
    - Мощность алфавита: {charset_size} символов
    - Пространство ключей: {keyspace:.2e} комбинаций
    - Энтропия: {entropy:.2f} бит

2. ОЦЕНКА ВРЕМЕНИ ПОДБОРА ДЛЯ РАЗНЫХ СЦЕНАРИЕВ:
"""
        for name, data in times.items():
            report += f"""
    [{name}]:
    - В секундах: {'∞' if data['seconds'] == float('inf') else f'{data["seconds"]:.2f}'}
    - В годах: {'∞' if data['years'] == float('inf') else f'{data["years"]:.2f}'}
"""

        report += f"""
3. ОБНАРУЖЕННЫЕ УЯЗВИМОСТИ:
"""
        if issues:
            for issue in issues:
                report += f"   - {issue}\n"
        else:
            report += "   - Уязвимости не обнаружены\n"

        report += f"""
4. РЕКОМЕНДАЦИИ ПО УЛУЧШЕНИЮ ПАРОЛЯ:
"""
        if suggestions:
            for suggestion in suggestions:
                report += f"   - {suggestion}\n"
        else:
            report += "   - Пароль соответствует базовым требованиям стойкости.\n"

        report += f"""
5. ОБЩАЯ ОЦЕНКА СТОЙКОСТИ (по сценарию «Кластер/ASIC»): {strength}

ВНИМАНИЕ: при словарных и гибридных атаках время брутфорс‑атаки может быть многократно меньше!
Избегайте словарных шаблонов и их модификаций!

"""
        return report


def generate_general_recommendations_csv(output_file: str):
    """
    Генерирует CSV‑файл с памяткой по созданию стойких паролей.
    Содержит 10 категорий рекомендаций с пояснениями.
    """
    recommendations = [
        {
            "forbidden": "НЕ ИСПОЛЬЗУЙТЕ короткие пароли (менее 10 символов)",
            "necessary": "ИСПОЛЬЗУЙТЕ пароли длиной не менее 10 символов",
            "explanation": "Каждый дополнительный символ экспоненциально увеличивает время подбора, 10+ символов — безопасная длина."
        },
        {
            "forbidden": "НЕ ИСПОЛЬЗУЙТЕ однотипные символы (только цифры или только буквы)",
            "necessary": "ИСПОЛЬЗУЙТЕ буквы разного регистра, цифры и специальные символы",
            "explanation": "Разнообразие символов увеличивает мощность алфавита и сильно усложняет брутфорс-атаку."
        },
        {
            "forbidden": "НЕ ИСПОЛЬЗУЙТЕ распространённые слова, даже с заменой символов (leetspeak)",
            "necessary": "СОЗДАВАЙТЕ случайные комбинации символов, не имеющие смысла",
            "explanation": "Словарные атаки и их модификации обходят такие замены, пароль подбирается за секунды."
        },
        {
            "forbidden": "НЕ ИСПОЛЬЗУЙТЕ простые последовательности (12345, qwerty, abcde)",
            "necessary": "ИСПОЛЬЗУЙТЕ хаотичные наборы символов",
            "explanation": "Распространённые последовательности проверяются в первую очередь и подбираются мгновенно."
        },
        {
            "forbidden": "НЕ ИСПОЛЬЗУЙТЕ один и тот же пароль для нескольких аккаунтов",
            "necessary": "СОЗДАВАЙТЕ уникальный пароль для каждого сервиса",
            "explanation": "Компрометация одного пароля не должна затрагивать другие ваши аккаунты."
        },
        {
            "forbidden": "НЕ ОСТАВЛЯЙТЕ пароль неизменным годами",
            "necessary": "МЕНЯЙТЕ пароли не реже чем раз в 6 месяцев",
            "explanation": "Регулярная смена снижает риски от возможных утечек данных."
        },
        {
            "forbidden": "НЕ ИГНОРИРУЙТЕ показатель энтропии",
            "necessary": "СТРЕМИТЕСЬ к энтропии пароля не менее 60-70 бит",
            "explanation": "Энтропия отражает случайность пароля. Чем она выше, тем сложнее перебор."
        },
        {
            "forbidden": "НЕ ИСПОЛЬЗУЙТЕ одинаковую сложность для всех данных",
            "necessary": "УЧИТЫВАЙТЕ критичность защищаемых данных при выборе пароля",
            "explanation": "Для банковских и почтовых аккаунтов используйте самые сложные пароли."
        },
        {
            "forbidden": "НЕ ПОЛАГАЙТЕСЬ только на свою интуицию",
            "necessary": "ПРОВЕРЯЙТЕ пароль через Automated_password_strength_assessment_system.py",
            "explanation": "Консольное приложение покажет конкретные уязвимости и примерное время взлома."
        },
        {
            "forbidden": "НЕ ИСПОЛЬЗУЙТЕ кириллицу в паролях",
            "necessary": "ИСПОЛЬЗУЙТЕ ТОЛЬКО латинские буквы, цифры и спецсимволы",
            "explanation": "Кириллица не поддерживается большинством систем и делает пароль несовместимым. Брутфорс-атаки по латинице её не подберут, но это не признак надёжности."
        }
    ]

    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            f.write("Памятка по созданию устойчивых к брутфорс-атакам паролей\n\n")
            fieldnames = ["ЗАПРЕЩЕНО", "НЕОБХОДИМО", "ПОЯСНЕНИЕ"]
            writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=';')
            writer.writeheader()
            for rec in recommendations:
                writer.writerow({
                    "ЗАПРЕЩЕНО": rec["forbidden"],
                    "НЕОБХОДИМО": rec["necessary"],
                    "ПОЯСНЕНИЕ": rec["explanation"]
                })
        print(f"\n Памятка сохранена в файл: {output_file}")
        print("-" * 80)
    except Exception as e:
        print(f"Ошибка при записи CSV: {e}")


def main():
    """
    Главная функция: обрабатывает аргументы командной строки,
    запускает интерактивный режим или генерацию CSV‑памятки.
    """
    parser = argparse.ArgumentParser(
        description="Система оценки устойчивости паролей к брутфорс-атакам",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  python Automated_password_strength_assessment_system.py  # Интерактивный режим
  python Automated_password_strength_assessment_system.py --recommendations      # Получить CSV с памяткой
  python Automated_password_strength_assessment_system.py --output recs.csv      # Сохранить памятку в файл
        """
    )

    parser.add_argument(
        "--recommendations", action="store_true",
        help="Сгенерировать CSV-файл с памяткой по созданию стойких паролей"
    )

    parser.add_argument(
        "--output", type=str, default="password_recommendations.csv",
        help="Имя выходного CSV‑файла (по умолчанию: password_recommendations.csv)"
    )

    args = parser.parse_args()
    analyzer = PasswordAnalyzer()

    if args.recommendations:
        generate_general_recommendations_csv(args.output)
    else:
       
        print("Добро пожаловать в СИСТЕМУ ОЦЕНКИ УСТОЙЧИВОСТИ ПАРОЛЕЙ К БРУТФОРС-АТАКАМ!")
        print(f"\n")
        print("~" * 100)
        print(f"Automated_password_strength_assessment_system.py")
        print("~" * 100)
        print(f"\nВНИМАНИЕ: Вводимые пароли не сохраняются и не передаются по сети!")
        print(f"ВНИМАНИЕ: В пароле допустимы только латинские буквы, цифры и специальные символы, \nтак как кириллица в паролях не поддерживается в большинстве современных систем из-за несовместимости.\n")
        print("\n                    ВОЗМОЖНОСТИ СИСТЕМЫ:")
        print(f"\nОценить устойчивость пароля к брутфорс-атакам")
        print(f"\nПолучить памятку по созданию устойчивых паролей (команда 'рекомендации', 'recommendation','r')")
        print(f"\nВыйти из программы (команда 'выход', 'exit')")
        

        while True:
            try:
                user_input = input("\nВведите пароль для проверки,'рекомендации'или'выход': ").strip()

                if user_input.lower() in ['выход', 'quit', 'exit', 'q']:
                    print("\nДо свидания! Спасибо за использование системы.")
                    break

                if user_input.lower() in ['рекомендации', 'recommendations', 'recs', 'r']:
                    choice = input("\nХотите сохранить памятку в CSV файл? (да/нет): ").strip().lower()
                    if choice in ['да', 'yes', 'y', 'д']:
                        filename = input("Введите имя файла (по умолчанию: password_recommendations.csv): ").strip()
                        if not filename:
                            filename = "password_recommendations.csv"
                        generate_general_recommendations_csv(filename)
                    else:
                        print("\n" + "=" * 80)
                        print("ПАМЯТКА ПО СОЗДАНИЮ СТОЙКИХ ПАРОЛЕЙ (кратко)")
                        print("=" * 80)
                        tips = [
                            "1. Длина пароля: не менее 10 символов.",
                            "2. Используйте буквы разного регистра, цифры и спецсимволы.",
                            "3. Избегайте словарных слов и простых последовательностей.",
                            "4. Не повторяйте пароль на разных сайтах.",
                            "5. Регулярно меняйте пароли (раз в 6 месяцев).",
                            "6. Для важных аккаунтов используйте самые сложные пароли.",
                            "7. Проверяйте пароль через данную программу.",
                            "8. Используйте только латинские буквы (кириллица недопустима)."
                        ]
                        for tip in tips:
                            print(f"   {tip}")
                        print("=" * 80)
                    continue

                if not user_input:
                    print(" Ошибка: пароль не может быть пустым. Попробуйте ещё раз.")
                    continue

                report = analyzer.generate_report(user_input)
                print(report)

                print("\n" + "-" * 60)
                rec_choice = input("Хотите получить памятку по созданию устойчивых паролей? (да/нет): ").strip().lower()
                if rec_choice in ['да', 'yes', 'y', 'д']:
                    generate_general_recommendations_csv("password_recommendations.csv")

            except (KeyboardInterrupt, EOFError):
                print("\n\nРабота завершена пользователем.")
                break
            except Exception as e:
                print(f"\nПроизошла ошибка: {e}. Попробуйте снова.")


if __name__ == "__main__":
    main()
<img width="100%" alt="Cherry Blossom Pink GIF" src="https://github.com/user-attachments/assets/a9028254-fbc2-450c-b4a3-453a9633de91" />

### 🦠 YARA RULES 
Цей репозиторій створений для YARA-RULES і для підвищення кібербезпеки

Планую писати сюди багато YARA коду, дякую що читаєте це і можливо підтримуєте мене

Перший YARA-rule це [Generic_Malware.yar](https://github.com/blade391off/YARA-rules/blob/main/Generic/Generic_Malware.yar)

---
### About me 
Мені 11 років, я хочу стати вірусним аналітиком 

Я Тимофій, маю аккаунт на [DOU](https://dou.ua/users/blade391off/)

Хочу підвищити кібербезпеку в Україні!

--- 

### WARNING 

В проєкті ніколи не буде будь-яких файлів, максимум в майбутньому планую додати сюди пайтон код який об'єднує всі правила в один шматок

## Структура репо

```text
YARA-rules/                             # Корінь проекту
├── AUTHOR_CONTACT.md                   # Контактна інформація автора репозиторію для зв'язку
├── LICENSE                             # Ліцензія репозиторію (умови копіювання та використання)
├── README.md                           # Головна документація та інструкція всього проекту
│
├── Generic/                            # Папка універсальних правил
│   ├── Generic_Malware.yar             # Загальні сигнатури для виявлення різних типів шкідливого ПЗ
│   └── README.md                       # Опис логіки модифікації папки Generic
│
├── HackTools/                          # Папка утиліт для пентесту та пост-експлуатації
│   ├── Chisel_Ligolo.yar               # Виявлення інструментів мережевого туннелювання Chisel та Ligolo
│   ├── Cobalt_Strike.yar               # Сигнатури для детекції фреймворку Cobalt Strike
│   ├── Impacket_Tools.yar              # Обнаруження скриптів мережевого фреймворку Impacket
│   ├── Mimikatz.yar                    # Детекція утиліти для дампу паролів та токенів Mimikatz
│   ├── Silver_C2.yar                   # Сигнатури для командного сервера Sliver C2
│   └── README.md                       # Попередження про можливі хибні спрацьовування легітимного софту
│
├── Loader/                             # Папка завантажувачів та дропперів
│   ├── GCleaner.yar                    # Сигнатури для виявлення завантажувача/клінера GCleaner
│   ├── Generic_Loader.yar              # Універсальне правило для пошуку лоадерів загального типу
│   ├── Loader.yar                      # Базовий набір детекції шкідливих дропперів
│   └── README.md                       # Опис механізму роботи малварі типу Loader
│
├── Other/                              # Специфічні та нестандартні категорії загроз
│   ├── Wiper/                          # Піддиректорія для деструктивного ПЗ
│   │   └── 01Wiper.yar                 # Сигнатура для пошуку вайперів, що знищують дані на диску
│   ├── 01PUP.yar                       # Виявлення потенційно небажаних програм (Adware/Toolbar)
│   └── README.md                       # Заметка про класифікацію нестандартних файлів
│
├── Ransomware/                         # Програми-вимагачі (Шифрувальники)
│   ├── Petya/                          # Підпапка щодо відомої загрози Petya / NotPetya
│   │   ├── Deep.yar                    # Глубокий аналіз коду Petya з високим рівнем впевненості
│   │   ├── Production.yar              # Стабільні перевірені правила Petya для щоденного використання
│   │   └── Triage.yar                  # Швидкі поверхневі сигнатури Petya для первинного аналізу
│   └── README.md                       # Опис категорії ransomware та загроз для користувача
│
├── Stealers/                           # Інфостілери (Крадіжка куків, паролей та крипти)
│   ├── Racoon/                         # Сигнатури для інфостілера Raccoon Stealer
│   │   ├── Deep.yar                    # Складні сигнатури Raccoon для детального аналізу
│   │   ├── Production.yar              # Надійне правило Raccoon для постійного моніторингу
│   │   ├── Triage.yar                  # Швидке виявлення активності Raccoon у системі
│   │   └── README.md                   # Градація правил детекції Raccoon за рівнями
│   ├── RedLine/                        # Сигнатури для інфостілера RedLine Stealer
│   │   ├── Deep.yar                    # Глубокий реверс-аналіз сигнатур RedLine
│   │   ├── Production.yar              # Стабільний повсякденний детект родини RedLine
│   │   ├── Triage.yar                  # Первичне експрес-виявлення індикаторів RedLine
│   │   └── README.md                   # Справка за рівнями аналізу малварі RedLine
│   └── README.md                       # Загальний опис папки для збору сигнатур інфостілерів
│
├── Trojans/                            # Класичні трояни та RAT-програми
│   ├── RAT/                            # Підпапка для троянів віддаленого доступу (Remote Access Trojans)
│   │   ├── AsyncRAT.yar                # Детекція популярного RAT-трояна AsyncRAT
│   │   ├── DarkComet.yar               # Сигнатури для виявлення шкідливого софту DarkComet RAT
│   │   ├── NjRAT.yar                   # Пошук індикаторів зараження трояном NjRAT
│   │   └── QuasarRAT.yar               # Виявлення утиліти віддаленого адміністрування Quasar RAT
│   ├── Agent_Tesla.yar                 # Пошук шпигунського ПЗ та стилера Agent Tesla
│   ├── Carberp.yar                     # Виявлення банківського трояна Carberp
│   ├── Default_Trojan.yar              # Базові універсальні сигнатури для детекції троянів
│   ├── Emotet.yar                      # Пошук компонентів ботнету та модульного трояна Emotet
│   ├── Fake_Antivirus.yar              # Детекція фальшивих антивірусів (Scareware)
│   ├── MEMZ_Trojan.yar                 # Сигнатури деструктивного трояна MEMZ, що руйнує завантажувач MBR
│   ├── ZEUS.yar                        # Виявлення відомого банківського трояна Zeus (Zbot)
│   └── README.MD                       # Опис папки з відомими троянами та RAT
│
└── WinLock/                            # Блокувальники екрану (Вінлокери)
    ├── NavalnyPass_2000.yar            # Сигнатура кастомного вимагача / стілера паролів
    ├── Winlock5413.yar                 # Детекція екранного блокиратора Winlock версії 5413
    ├── Winlock_uxCryptor.yar           # Виявлення модифікації локера uxCryptor
    └── README.md                       # Визначення та принципи роботи вірусів типу WinLocker
```



---

### LICENSE 
Проєкт поширюється відповідно до умов MIT LICENSE
<details>
<summary><b>Натисніть, щоб розгорнути текст ліцензії</b></summary>

---
MIT License

Copyright (c) 2026 blade

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

***

**END OF LICENSE**



</details>



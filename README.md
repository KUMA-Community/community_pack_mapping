# community_pack_mapping
Скрипт для мапинга правил комьюнити на новый способ, добавленный в KUMA 3.2
# Описание
Данный скрипт предназначен для маппинга правил корреляции новым способом, добавленным в KUMA 3.2, который позволяет экспортировать покрытие правил для использование в MITRE Navigator. Скрипт расшифровывает экспортированные ресурсы из KUMA, просматривает настроенное обогащение правил и берет во внимание только constant и поле Technique. На основании этих данных и техник, известных KUMA, скрипт размечает новым способом правила, после чего зашифровывает обратно файл ресурсов.
# Ограничения
Скрипт предназначен исключительно для Community Pack, т.к. для поиска техник используется регулярное выражение, подходящее под наш пакет правил. Если вы хотите адаптировать скрипт под свои правила, то используемое регулярное выражение можно переопределить в переменной `RE_STRING` в скрипте `kuma_remapper.py`
# Требования
## Требования к ресурсам
1. Для работы скрипта необходим файл `mitre.json` содержащий техники и тактики, о которых знает KUMA.

Для его получения, необходимо согласно инструкции импортировать в KUMA актуальное покрытие (см. онлайн-справку). После этого на сервере ядра KUMA выполнить команду:

```
/opt/kaspersky/kuma/mongodb/bin/mongo localhost/kuma --quiet --eval 'db.mitre.find({},{"_id":0}).toArray()' > mitre.json
```

2. Для работы скрипта также необходим файл ресурсов, экспортированный из KUMA, содержащий правила корреляции, которые необходимо "переразметить"

Все ресурсы кроме правил корреляции будут проигнорированы скриптом, так что за них можно не переживать.

## Требования к ПО
python 3.12+
- json
- re
- argparse
- codecs
- os
- light_crypter (нужный файл уже есть в данном репозитории)
# Использование скрипта
## Подготовка
1. Поместите содержимое репозитория в удобную папку
2. Подготовьте файл mitre.json по инструкции из шага 1. Требований к ресурсам
3. Экспортируйте требуемые правила корреляции из KUMA
4. Запустите скрипт, передав необходимые аргументы
5. ???
6. PROFIT
## Аргументы скрипта
```
options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Path to KUMA resource file exported from WebUI
  -p PASSWORD, --password PASSWORD
                        Password for decrypt and encrypt KUMA resource file
  -m MITRE, --mitre MITRE
                        Path to MITRE mapping from KUMA.
  --output OUTPUT       (Optional) Path to output file. Default: remappedRules

```
## Пример
```
python kuma_remapper.py -i ExportedResource -p SuperSecurePassword -m mitre.json --output RemappedRules
```
## Результат
В результате работы скрипта в директории запуска будет создан файл `remappedRules` (если не был переопределен в параметре `output`), содержащий все исходные ресурсы с новым способом мапинга правил.

# Благодарности
Спасибо [Morpheme777](https://github.com/Morpheme777) за скрипт шифрования/дешифрования ресурсов KUMA, который не перестает нас радовать :)

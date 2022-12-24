from datetime import datetime
from hashlib import sha256
from json import load as json_load, dump as json_dump
from os.path import join, dirname
from urllib.request import Request, urlopen
from bs4 import BeautifulSoup
from logging import basicConfig as log_basicConfig, INFO as LOG_INFO, error as log_error
log_basicConfig(filename='mensa.log', format='%(asctime)s\t%(message)s', datefmt='%Y-%m-%d_%H-%M-%S', level=LOG_INFO)

_mensa_url = 'https://kantonsschule-alpenquai.sv-restaurant.ch/de/menuplan/'
_mensa_url_robots = 'https://kantonsschule-alpenquai.sv-restaurant.ch/robots.txt'
_mensa_agent = 'Mozilla/5.0 (compatible; Python-urllib/3.10; Dieser Roboter lädt automatisch den Menüplan herunter.)'


def get_current_time():
    return datetime.now().strftime('%Y-%m-%d_%H-%M-%S')


def main():
    try:
        req = Request(_mensa_url_robots, headers={'User-Agent': _mensa_agent})
        robots = urlopen(req)
        if sha256(robots.read()).hexdigest() != '64f40283f2f694942ae7bff26e774ef3dafb41949d75a7e7c23d5db1bee217b2':
            log_error('mensa robots.txt has changed')
            return None
        req = Request(_mensa_url, headers={'User-Agent': _mensa_agent})
        html_page = urlopen(req)
        soup = BeautifulSoup(html_page, "html.parser")
        container = soup.find('div', class_='menu-plan-tabs')
        titles = []
        texts = []
        days = []
        for i in range(1, 6):
            try:
                titles.append([])
                texts.append([])
                j = container.findChild('div', id=f"menu-plan-tab{i}", class_='menu-plan-grid')
                for a in j.findChildren('div', class_='menu-item'):
                    b = a.findChild('div', class_='item-content')
                    titles[-1].append(b.findChild('h2', class_='menu-title').getText())
                    texts[-1].append(b.findChild('p', class_='menu-description').getText().replace('\n', ' '))
            except Exception as error:
                log_error(error)
        container2 = soup.find('div', class_='day-nav')
        container3 = container2.findChild('ul', class_='no-bullets is-horizontal')
        for i in container3.findChildren('li'):
            j = i.findChild('label')
            days.append(j.getText().replace('\n', ' '))
        add_content = {}
        for i, day in enumerate(days):
            for j in range(len(titles[i])):
                try:
                    add_content[f"{get_current_time()}_{i}-{j}"] = {'date': day, 'title': titles[i][j],
                                                                    'menu': texts[i][j]}
                except Exception as error:
                    log_error(error)
        with open(join(dirname(__file__), 'resources/mensa.json'), 'r') as f:
            content = json_load(f)
        content |= add_content
        with open(join(dirname(__file__), 'resources/mensa.json'), 'w') as f:
            json_dump(content, f, indent=4)
    except Exception as error:
        log_error(error)


if __name__ == '__main__':
    main()

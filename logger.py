import logging

logger = logging.getLogger('weibo')
logger.setLevel(logging.DEBUG)

f_handler = logging.FileHandler('log.out','a','utf-8',False)
f_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
f_handler.setFormatter(formatter)
logger.addHandler(f_handler)
from setuptools import setup, find_packages
import sys, os

version = '0.1'

def read(fname):
    # read the contents of a text file
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

install_requires = [
    'Django>= 1.3'
]

setup(name='django-twostepauth',
      version=version,
      description="Two-step authentication for Django",
      long_description=read('README.rst'),
      platforms=['OS Independent'],
      classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Framework :: Django',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP',
      ], 
      keywords='django,authentication',
      author='Nuno Maltez, Pedro Lima',
      author_email='nuno@cognitiva.com, pedro@cognitiva.com',
      url='https://bitbucket.org/cogni/django-twostepauth',
      license='BSD',
      packages=find_packages(exclude=['exampleapp']),
      include_package_data=True,
      zip_safe=False,
      install_requires=install_requires,
      entry_points="""
      # -*- Entry points: -*-
      """,
      )

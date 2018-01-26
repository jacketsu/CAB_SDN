from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext

# setup(ext_modules = cythonize(
#     "CABcython.pyx",
#     sources=["CABcython.cpp"],
#     language="c++",
#     include_dirs=['../cab/'],
#     libraries=['cab']
#     ))

ext_modules = [
        Extension(name='pyCABcython',
            sources=['pyCABcython.pyx', 'CABcython.cpp'],
            language="c++",
            include_dirs=['../cab/'],
            runtime_library_dirs=['.'],
            extra_compile_args=["-std=c++11"], 
            extra_link_args=["-std=c++11"],
            library_dirs=['.'],
            libraries=['cab']
            )
        ]

setup(
        name = 'CABcython',
        ext_modules = ext_modules,
        cmdclass = {'build_ext': build_ext}
        )

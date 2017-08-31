import os
import sys

# In order to be able to run without pyelftools installed via pip, add path to
# local pyelftools submodule to PYTHONPATH
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__),
                                '..', 'pyelftools')))

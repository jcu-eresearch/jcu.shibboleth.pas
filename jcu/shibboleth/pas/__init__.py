import install

install.register_pas_plugin()

def initialize(context):
    """Initializer called when used as a Zope 2 product."""
    install.register_pas_plugin_class(context)

"""
hooks_for_edu_domains
"""

from yoyo import step

__depends__ = {'20240819_01_p2vXR-create-forgot-password-tokens-table'}

steps = [
    step(
        """
        INSERT INTO roles(role_id, role_name, user_editable) VALUES
            ('9bb203a2-7897-4fe3-ac4a-75e6a4f96f5d', 'hook-role-from-edu-domain', '0')
        """,
        "DELETE FROM roles WHERE role_name='hook-role-from-edu-domain'"),
    step(
        """
        INSERT INTO role_privileges(role_id, privilege_id) VALUES
            ('9bb203a2-7897-4fe3-ac4a-75e6a4f96f5d', 'group:resource:view-resource'),
            ('9bb203a2-7897-4fe3-ac4a-75e6a4f96f5d', 'group:resource:edit-resource')
        """,
        "DELETE FROM role_privileges WHERE role_id='9bb203a2-7897-4fe3-ac4a-75e6a4f96f5d'"
        )
]

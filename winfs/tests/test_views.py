from django.core.management import call_command
from django.urls import reverse

from winfs.constants import ACE_ALLOW, R, RC, SID_OWNER_RIGHTS, WD
from winfs.evaluate import ERR_OWNER_RIGHTS, access_check
from winfs.fixtures import add_ace_raw, allow, deny, sid

from .support import FixtureMixin, PostgresTestCase


class BrowserTests(FixtureMixin, PostgresTestCase):
    def test_authorized_browse_and_forbidden_child(self):
        allow(self.vol, self.eng, R, ci=True)
        allow(self.proj, self.eng, R, oi=True, ci=True)
        self.client.force_login(self.alice)
        volumes = self.client.get(reverse("winfs-volumes"))
        self.assertEqual(volumes.status_code, 200)
        self.assertContains(volumes, "vol")
        root = self.client.get(reverse("winfs-volume", args=[self.data["volume"].pk]))
        self.assertEqual(root.status_code, 200)
        proj = self.client.get(reverse("winfs-node", args=[self.proj.pk]))
        self.assertEqual(proj.status_code, 200)
        self.assertContains(proj, "readme.txt")
        self.assertContains(proj, "secret")
        notes = self.client.get(reverse("winfs-node", args=[self.notes.pk]))
        self.assertEqual(notes.status_code, 200)
        self.client.force_login(self.carol)
        denied = self.client.get(reverse("winfs-node", args=[self.notes.pk]))
        self.assertEqual(denied.status_code, 403)

    def test_anonymous_winfs_redirects_to_login(self):
        response = self.client.get(reverse("winfs-volumes"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("/accounts/login/", response.url)

    def test_volume_names_are_visible_without_accesscheck(self):
        allow(self.vol, self.eng, R, ci=True)
        self.client.force_login(self.carol)
        volumes = self.client.get(reverse("winfs-volumes"))
        self.assertEqual(volumes.status_code, 200)
        self.assertContains(volumes, "vol")
        denied = self.client.get(reverse("winfs-volume", args=[self.data["volume"].pk]))
        self.assertEqual(denied.status_code, 403)

    def test_owner_pregrant_is_not_list(self):
        self.client.force_login(self.admin)
        denied = self.client.get(reverse("winfs-volume", args=[self.data["volume"].pk]))
        self.assertEqual(denied.status_code, 403)
        rc = access_check(self.admin, self.vol, RC)
        wd = access_check(self.admin, self.vol, WD)
        self.assertTrue(rc.allowed)
        self.assertTrue(wd.allowed)

    def test_list_folder_does_not_reveal_denied_children(self):
        allow(self.proj, self.eng, R, oi=True, ci=True)
        deny(self.readme, self.data["bob"], R)
        self.client.force_login(self.bob)
        proj = self.client.get(reverse("winfs-node", args=[self.proj.pk]))
        self.assertEqual(proj.status_code, 200)
        self.assertContains(proj, "secret")
        self.assertNotContains(proj, "readme.txt")
        self.assertEqual(
            self.client.get(reverse("winfs-node", args=[self.readme.pk])).status_code,
            403,
        )

    def test_owner_rights_node_is_forbidden(self):
        allow(self.notes, self.data["alice"], R)
        add_ace_raw(
            self.notes.security_descriptor,
            ACE_ALLOW,
            sid(SID_OWNER_RIGHTS),
            WD,
        )
        decision = access_check(self.alice, self.notes, R)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.error, ERR_OWNER_RIGHTS)
        self.client.force_login(self.alice)
        response = self.client.get(reverse("winfs-node", args=[self.notes.pk]))
        self.assertEqual(response.status_code, 403)


class SeededBrowserTests(PostgresTestCase):
    def setUp(self):
        super().setUp()
        call_command("seed_winfs")
        from django.contrib.auth import get_user_model
        from winfs.models import WinNode, WinVolume

        User = get_user_model()
        self.alice = User.objects.get(username="alice")
        self.carol = User.objects.get(username="carol")
        self.admin = User.objects.get(username="admin")
        self.volume = WinVolume.objects.get(name="vol")
        self.vol = WinNode.objects.get(volume=self.volume, parent__isnull=True)
        self.notes = WinNode.objects.get(volume=self.volume, name="notes.txt")

    def test_seeded_alice_password_login_and_notes(self):
        login = self.client.post(
            reverse("login"),
            {"username": "alice", "password": "demo"},
        )
        self.assertEqual(login.status_code, 302)
        self.assertEqual(login.url, "/winfs/")
        volumes = self.client.get(reverse("winfs-volumes"))
        self.assertEqual(volumes.status_code, 200)
        root = self.client.get(reverse("winfs-volume", args=[self.volume.pk]))
        self.assertEqual(root.status_code, 200)
        notes = self.client.get(reverse("winfs-node", args=[self.notes.pk]))
        self.assertEqual(notes.status_code, 200)
        self.assertContains(notes, "RC")
        self.assertContains(notes, "True")

    def test_seeded_carol_and_admin_limitations(self):
        self.client.force_login(self.carol)
        self.assertEqual(self.client.get(reverse("winfs-volumes")).status_code, 200)
        self.assertEqual(
            self.client.get(reverse("winfs-volume", args=[self.volume.pk])).status_code,
            403,
        )
        self.assertEqual(
            self.client.get(reverse("winfs-node", args=[self.notes.pk])).status_code,
            403,
        )
        self.client.force_login(self.admin)
        self.assertEqual(
            self.client.get(reverse("winfs-volume", args=[self.volume.pk])).status_code,
            403,
        )

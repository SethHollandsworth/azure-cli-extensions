# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import os
import unittest
import pytest
import json
import deepdiff
import docker

from azext_confcom.security_policy import (
    OutputType,
    load_policy_from_image_name,
)
import azext_confcom.config as config

TEST_DIR = os.path.abspath(os.path.join(os.path.abspath(__file__), ".."))


# @unittest.skip("not in use")
@pytest.mark.run(order=1)
class PolicyGeneratingImage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with load_policy_from_image_name("python:3.6.14-slim-buster") as aci_policy:
            aci_policy.populate_policy_content_for_all_images(individual_image=True)
            cls.aci_policy = aci_policy

    def test_image_policy(self):
        expected_policy = "cGFja2FnZSBwb2xpY3kKCmltcG9ydCBmdXR1cmUua2V5d29yZHMuZXZlcnkKaW1wb3J0IGZ1dHVyZS5rZXl3b3Jkcy5pbgoKYXBpX3N2biA6PSAiMC4xMC4wIgpmcmFtZXdvcmtfc3ZuIDo9ICIwLjIuMCIKCmZyYWdtZW50cyA6PSBbCiAgewogICAgImZlZWQiOiAibWNyLm1pY3Jvc29mdC5jb20vYWNpL2FjaS1jYy1pbmZyYS1mcmFnbWVudCIsCiAgICAiaW5jbHVkZXMiOiBbCiAgICAgICJjb250YWluZXJzIgogICAgXSwKICAgICJpc3N1ZXIiOiAiZGlkOng1MDk6MDpzaGEyNTY6SV9faXVMMjVvWEVWRmRUUF9hQkx4X2VUMVJQSGJDUV9FQ0JRZllacHQ5czo6ZWt1OjEuMy42LjEuNC4xLjMxMS43Ni41OS4xLjMiLAogICAgIm1pbmltdW1fc3ZuIjogIjEuMC4wIgogIH0KXQoKY29udGFpbmVycyA6PSBbeyJhbGxvd19lbGV2YXRlZCI6dHJ1ZSwiYWxsb3dfc3RkaW9fYWNjZXNzIjp0cnVlLCJjYXBhYmlsaXRpZXMiOnsiYW1iaWVudCI6W10sImJvdW5kaW5nIjpbIkNBUF9BVURJVF9XUklURSIsIkNBUF9DSE9XTiIsIkNBUF9EQUNfT1ZFUlJJREUiLCJDQVBfRk9XTkVSIiwiQ0FQX0ZTRVRJRCIsIkNBUF9LSUxMIiwiQ0FQX01LTk9EIiwiQ0FQX05FVF9CSU5EX1NFUlZJQ0UiLCJDQVBfTkVUX1JBVyIsIkNBUF9TRVRGQ0FQIiwiQ0FQX1NFVEdJRCIsIkNBUF9TRVRQQ0FQIiwiQ0FQX1NFVFVJRCIsIkNBUF9TWVNfQ0hST09UIl0sImVmZmVjdGl2ZSI6WyJDQVBfQVVESVRfV1JJVEUiLCJDQVBfQ0hPV04iLCJDQVBfREFDX09WRVJSSURFIiwiQ0FQX0ZPV05FUiIsIkNBUF9GU0VUSUQiLCJDQVBfS0lMTCIsIkNBUF9NS05PRCIsIkNBUF9ORVRfQklORF9TRVJWSUNFIiwiQ0FQX05FVF9SQVciLCJDQVBfU0VURkNBUCIsIkNBUF9TRVRHSUQiLCJDQVBfU0VUUENBUCIsIkNBUF9TRVRVSUQiLCJDQVBfU1lTX0NIUk9PVCJdLCJpbmhlcml0YWJsZSI6W10sInBlcm1pdHRlZCI6WyJDQVBfQVVESVRfV1JJVEUiLCJDQVBfQ0hPV04iLCJDQVBfREFDX09WRVJSSURFIiwiQ0FQX0ZPV05FUiIsIkNBUF9GU0VUSUQiLCJDQVBfS0lMTCIsIkNBUF9NS05PRCIsIkNBUF9ORVRfQklORF9TRVJWSUNFIiwiQ0FQX05FVF9SQVciLCJDQVBfU0VURkNBUCIsIkNBUF9TRVRHSUQiLCJDQVBfU0VUUENBUCIsIkNBUF9TRVRVSUQiLCJDQVBfU1lTX0NIUk9PVCJdfSwiY29tbWFuZCI6WyJweXRob24zIl0sImVudl9ydWxlcyI6W3sicGF0dGVybiI6IlBBVEg9L3Vzci9sb2NhbC9iaW46L3Vzci9sb2NhbC9zYmluOi91c3IvbG9jYWwvYmluOi91c3Ivc2JpbjovdXNyL2Jpbjovc2JpbjovYmluIiwicmVxdWlyZWQiOmZhbHNlLCJzdHJhdGVneSI6InN0cmluZyJ9LHsicGF0dGVybiI6IkxBTkc9Qy5VVEYtOCIsInJlcXVpcmVkIjpmYWxzZSwic3RyYXRlZ3kiOiJzdHJpbmcifSx7InBhdHRlcm4iOiJHUEdfS0VZPTBEOTZERjRENDExMEU1QzQzRkJGQjE3RjJEMzQ3RUE2QUE2NTQyMUQiLCJyZXF1aXJlZCI6ZmFsc2UsInN0cmF0ZWd5Ijoic3RyaW5nIn0seyJwYXR0ZXJuIjoiUFlUSE9OX1ZFUlNJT049My42LjE0IiwicmVxdWlyZWQiOmZhbHNlLCJzdHJhdGVneSI6InN0cmluZyJ9LHsicGF0dGVybiI6IlBZVEhPTl9QSVBfVkVSU0lPTj0yMS4yLjQiLCJyZXF1aXJlZCI6ZmFsc2UsInN0cmF0ZWd5Ijoic3RyaW5nIn0seyJwYXR0ZXJuIjoiUFlUSE9OX0dFVF9QSVBfVVJMPWh0dHBzOi8vZ2l0aHViLmNvbS9weXBhL2dldC1waXAvcmF3L2MyMGIwY2ZkNjQzY2Q0YTE5MjQ2Y2NmMjA0ZTI5OTdhZjcwZjZiMjEvcHVibGljL2dldC1waXAucHkiLCJyZXF1aXJlZCI6ZmFsc2UsInN0cmF0ZWd5Ijoic3RyaW5nIn0seyJwYXR0ZXJuIjoiUFlUSE9OX0dFVF9QSVBfU0hBMjU2PWZhNmYzZmI5M2NjZTIzNGNkNGU4ZGQyYmViNTRhNTFhYjljMjQ3NjUzYjUyODU1YTQ4ZGQ0NGU2YjIxZmYyOGIiLCJyZXF1aXJlZCI6ZmFsc2UsInN0cmF0ZWd5Ijoic3RyaW5nIn0seyJwYXR0ZXJuIjoiVEVSTT14dGVybSIsInJlcXVpcmVkIjpmYWxzZSwic3RyYXRlZ3kiOiJzdHJpbmcifSx7InBhdHRlcm4iOiIoKD9pKUZBQlJJQylfLis9LisiLCJyZXF1aXJlZCI6ZmFsc2UsInN0cmF0ZWd5IjoicmUyIn0seyJwYXR0ZXJuIjoiSE9TVE5BTUU9LisiLCJyZXF1aXJlZCI6ZmFsc2UsInN0cmF0ZWd5IjoicmUyIn0seyJwYXR0ZXJuIjoiVChFKT9NUD0uKyIsInJlcXVpcmVkIjpmYWxzZSwic3RyYXRlZ3kiOiJyZTIifSx7InBhdHRlcm4iOiJGYWJyaWNQYWNrYWdlRmlsZU5hbWU9LisiLCJyZXF1aXJlZCI6ZmFsc2UsInN0cmF0ZWd5IjoicmUyIn0seyJwYXR0ZXJuIjoiSG9zdGVkU2VydmljZU5hbWU9LisiLCJyZXF1aXJlZCI6ZmFsc2UsInN0cmF0ZWd5IjoicmUyIn0seyJwYXR0ZXJuIjoiSURFTlRJVFlfQVBJX1ZFUlNJT049LisiLCJyZXF1aXJlZCI6ZmFsc2UsInN0cmF0ZWd5IjoicmUyIn0seyJwYXR0ZXJuIjoiSURFTlRJVFlfSEVBREVSPS4rIiwicmVxdWlyZWQiOmZhbHNlLCJzdHJhdGVneSI6InJlMiJ9LHsicGF0dGVybiI6IklERU5USVRZX1NFUlZFUl9USFVNQlBSSU5UPS4rIiwicmVxdWlyZWQiOmZhbHNlLCJzdHJhdGVneSI6InJlMiJ9LHsicGF0dGVybiI6ImF6dXJlY29udGFpbmVyaW5zdGFuY2VfcmVzdGFydGVkX2J5PS4rIiwicmVxdWlyZWQiOmZhbHNlLCJzdHJhdGVneSI6InJlMiJ9XSwiZXhlY19wcm9jZXNzZXMiOltdLCJpZCI6InB5dGhvbjozLjYuMTQtc2xpbS1idXN0ZXIiLCJsYXllcnMiOlsiMjU0Y2M4NTNkYTYwODE5MDVjOTEwOWM4YjlkOTljOWZiMDk4N2JhMWQ4OGY3MjkwODg5MDNjZmZiODBmNTVmMSIsImE1NjhmMTkwMGJlZDYwYTA2NDFiNzZiOTkxYWQ0MzE0NDZkOWMzYTM0NGQ3YjI2MWYxMGRlOGQ4ZTczNzYzYWMiLCJjNzBjNTMwZTg0MmY2NjIxNWIwYmQ5NTU4NzcxNTdiYTI0YzM3OTkzMDM1NjdjM2Y1NjczYzQ1NjYzZWE0ZDE1IiwiM2U4NmMzY2NmMTY0MmJmNTg0ZGUzM2I0OWM3MjQ4Zjg3ZWVjZDBmNmQ4YzA4MzUzZGFhMzZjYzdhZDBhN2I2YSIsIjFlNDY4NGQ4YzdjYWE3NGM2NTI0MTcyYjRkNWExNTlhMTA4ODc2MTNlZDcwZjE4ZDBhNTVkMDViMmFmNjFhY2QiXSwibW91bnRzIjpbeyJkZXN0aW5hdGlvbiI6Ii9ldGMvcmVzb2x2LmNvbmYiLCJvcHRpb25zIjpbInJiaW5kIiwicnNoYXJlZCIsInJ3Il0sInNvdXJjZSI6InNhbmRib3g6Ly8vdG1wL2F0bGFzL3Jlc29sdmNvbmYvLisiLCJ0eXBlIjoiYmluZCJ9XSwibm9fbmV3X3ByaXZpbGVnZXMiOnRydWUsInNlY2NvbXBfcHJvZmlsZV9zaGEyNTYiOiIiLCJzaWduYWxzIjpbXSwidXNlciI6eyJncm91cF9pZG5hbWVzIjpbeyJwYXR0ZXJuIjoiIiwic3RyYXRlZ3kiOiJhbnkifV0sInVtYXNrIjoiMDAyMiIsInVzZXJfaWRuYW1lIjp7InBhdHRlcm4iOiIiLCJzdHJhdGVneSI6ImFueSJ9fSwid29ya2luZ19kaXIiOiIvIn0seyJhbGxvd19lbGV2YXRlZCI6ZmFsc2UsImFsbG93X3N0ZGlvX2FjY2VzcyI6dHJ1ZSwiY29tbWFuZCI6WyIvcGF1c2UiXSwiZW52X3J1bGVzIjpbeyJwYXR0ZXJuIjoiUEFUSD0vdXNyL2xvY2FsL3NiaW46L3Vzci9sb2NhbC9iaW46L3Vzci9zYmluOi91c3IvYmluOi9zYmluOi9iaW4iLCJyZXF1aXJlZCI6dHJ1ZSwic3RyYXRlZ3kiOiJzdHJpbmcifSx7InBhdHRlcm4iOiJURVJNPXh0ZXJtIiwicmVxdWlyZWQiOmZhbHNlLCJzdHJhdGVneSI6InN0cmluZyJ9XSwiZXhlY19wcm9jZXNzZXMiOltdLCJsYXllcnMiOlsiMTZiNTE0MDU3YTA2YWQ2NjVmOTJjMDI4NjNhY2EwNzRmZDU5NzZjNzU1ZDI2YmZmMTYzNjUyOTkxNjllODQxNSJdLCJtb3VudHMiOltdLCJzaWduYWxzIjpbXSwid29ya2luZ19kaXIiOiIvIn1dCgphbGxvd19wcm9wZXJ0aWVzX2FjY2VzcyA6PSBmYWxzZQphbGxvd19kdW1wX3N0YWNrcyA6PSBmYWxzZQphbGxvd19ydW50aW1lX2xvZ2dpbmcgOj0gZmFsc2UKYWxsb3dfZW52aXJvbm1lbnRfdmFyaWFibGVfZHJvcHBpbmcgOj0gdHJ1ZQphbGxvd191bmVuY3J5cHRlZF9zY3JhdGNoIDo9IGZhbHNlCgoKCm1vdW50X2RldmljZSA6PSBkYXRhLmZyYW1ld29yay5tb3VudF9kZXZpY2UKdW5tb3VudF9kZXZpY2UgOj0gZGF0YS5mcmFtZXdvcmsudW5tb3VudF9kZXZpY2UKbW91bnRfb3ZlcmxheSA6PSBkYXRhLmZyYW1ld29yay5tb3VudF9vdmVybGF5CnVubW91bnRfb3ZlcmxheSA6PSBkYXRhLmZyYW1ld29yay51bm1vdW50X292ZXJsYXkKY3JlYXRlX2NvbnRhaW5lciA6PSBkYXRhLmZyYW1ld29yay5jcmVhdGVfY29udGFpbmVyCmV4ZWNfaW5fY29udGFpbmVyIDo9IGRhdGEuZnJhbWV3b3JrLmV4ZWNfaW5fY29udGFpbmVyCmV4ZWNfZXh0ZXJuYWwgOj0gZGF0YS5mcmFtZXdvcmsuZXhlY19leHRlcm5hbApzaHV0ZG93bl9jb250YWluZXIgOj0gZGF0YS5mcmFtZXdvcmsuc2h1dGRvd25fY29udGFpbmVyCnNpZ25hbF9jb250YWluZXJfcHJvY2VzcyA6PSBkYXRhLmZyYW1ld29yay5zaWduYWxfY29udGFpbmVyX3Byb2Nlc3MKcGxhbjlfbW91bnQgOj0gZGF0YS5mcmFtZXdvcmsucGxhbjlfbW91bnQKcGxhbjlfdW5tb3VudCA6PSBkYXRhLmZyYW1ld29yay5wbGFuOV91bm1vdW50CmdldF9wcm9wZXJ0aWVzIDo9IGRhdGEuZnJhbWV3b3JrLmdldF9wcm9wZXJ0aWVzCmR1bXBfc3RhY2tzIDo9IGRhdGEuZnJhbWV3b3JrLmR1bXBfc3RhY2tzCnJ1bnRpbWVfbG9nZ2luZyA6PSBkYXRhLmZyYW1ld29yay5ydW50aW1lX2xvZ2dpbmcKbG9hZF9mcmFnbWVudCA6PSBkYXRhLmZyYW1ld29yay5sb2FkX2ZyYWdtZW50CnNjcmF0Y2hfbW91bnQgOj0gZGF0YS5mcmFtZXdvcmsuc2NyYXRjaF9tb3VudApzY3JhdGNoX3VubW91bnQgOj0gZGF0YS5mcmFtZXdvcmsuc2NyYXRjaF91bm1vdW50CgpyZWFzb24gOj0geyJlcnJvcnMiOiBkYXRhLmZyYW1ld29yay5lcnJvcnN9"

        # deep diff the output policies from the regular policy.json and the ARM template
        aci_policy_str = self.aci_policy.get_serialized_output()
        self.assertEqual(aci_policy_str, expected_policy)


# @unittest.skip("not in use")
@pytest.mark.run(order=2)
class PolicyGeneratingImageSidecar(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with load_policy_from_image_name(
            "mcr.microsoft.com/aci/atlas-mount-azure-file-volume:master_20201210.2"
        ) as aci_policy:
            aci_policy.populate_policy_content_for_all_images(individual_image=True)
            cls.aci_policy = aci_policy

    def test_sidecar_image_policy(self):
        expected_policy = "cGFja2FnZSBtaWNyb3NvZnRjb250YWluZXJpbnN0YW5jZQoKc3ZuIDo9ICIxLjAuMCIKYXBpX3N2biA6PSAiMC4xMC4wIgpmcmFtZXdvcmtfc3ZuIDo9ICIwLjIuMCIKCmNvbnRhaW5lcnMgOj0gW3siYWxsb3dfZWxldmF0ZWQiOnRydWUsImFsbG93X3N0ZGlvX2FjY2VzcyI6dHJ1ZSwiY2FwYWJpbGl0aWVzIjp7ImFtYmllbnQiOltdLCJib3VuZGluZyI6WyJDQVBfQVVESVRfV1JJVEUiLCJDQVBfQ0hPV04iLCJDQVBfREFDX09WRVJSSURFIiwiQ0FQX0ZPV05FUiIsIkNBUF9GU0VUSUQiLCJDQVBfS0lMTCIsIkNBUF9NS05PRCIsIkNBUF9ORVRfQklORF9TRVJWSUNFIiwiQ0FQX05FVF9SQVciLCJDQVBfU0VURkNBUCIsIkNBUF9TRVRHSUQiLCJDQVBfU0VUUENBUCIsIkNBUF9TRVRVSUQiLCJDQVBfU1lTX0NIUk9PVCJdLCJlZmZlY3RpdmUiOlsiQ0FQX0FVRElUX1dSSVRFIiwiQ0FQX0NIT1dOIiwiQ0FQX0RBQ19PVkVSUklERSIsIkNBUF9GT1dORVIiLCJDQVBfRlNFVElEIiwiQ0FQX0tJTEwiLCJDQVBfTUtOT0QiLCJDQVBfTkVUX0JJTkRfU0VSVklDRSIsIkNBUF9ORVRfUkFXIiwiQ0FQX1NFVEZDQVAiLCJDQVBfU0VUR0lEIiwiQ0FQX1NFVFBDQVAiLCJDQVBfU0VUVUlEIiwiQ0FQX1NZU19DSFJPT1QiXSwiaW5oZXJpdGFibGUiOltdLCJwZXJtaXR0ZWQiOlsiQ0FQX0FVRElUX1dSSVRFIiwiQ0FQX0NIT1dOIiwiQ0FQX0RBQ19PVkVSUklERSIsIkNBUF9GT1dORVIiLCJDQVBfRlNFVElEIiwiQ0FQX0tJTEwiLCJDQVBfTUtOT0QiLCJDQVBfTkVUX0JJTkRfU0VSVklDRSIsIkNBUF9ORVRfUkFXIiwiQ0FQX1NFVEZDQVAiLCJDQVBfU0VUR0lEIiwiQ0FQX1NFVFBDQVAiLCJDQVBfU0VUVUlEIiwiQ0FQX1NZU19DSFJPT1QiXX0sImNvbW1hbmQiOlsiL21vdW50X2F6dXJlX2ZpbGUuc2giXSwiZW52X3J1bGVzIjpbeyJwYXR0ZXJuIjoiUEFUSD0vdXNyL2xvY2FsL3NiaW46L3Vzci9sb2NhbC9iaW46L3Vzci9zYmluOi91c3IvYmluOi9zYmluOi9iaW4iLCJyZXF1aXJlZCI6ZmFsc2UsInN0cmF0ZWd5Ijoic3RyaW5nIn1dLCJleGVjX3Byb2Nlc3NlcyI6W10sImlkIjoibWNyLm1pY3Jvc29mdC5jb20vYWNpL2F0bGFzLW1vdW50LWF6dXJlLWZpbGUtdm9sdW1lOm1hc3Rlcl8yMDIwMTIxMC4yIiwibGF5ZXJzIjpbIjYwNmZkNmJhZjVlYjFhNzFmZDI4NmFlYTI5NjcyYTA2YmZlNTVmMDAwN2RlZDkyZWU3MzE0MmEzNzU5MGVkMTkiLCIzYWQxYTJmZjRhNDRiYzg2MGIzY2QwMjdjYzg2Y2U0NWEzOTljNGM5OTVjMzZlOTgwMGM1MzY4Y2I3MjdhN2UxIiwiYjFjZmMzMGYzN2YwOGU2MDY2OGRiM2Y3MTYwNjk3YjE5ZDJhZDQ1YjEyZjA3NTE4ODUyOTkzNzM2MTZhNmUwYSIsImVmMzY0ODQ2YzhmMWY0M2QxNGQyZTNlNzkxOWEwNjRiMGM4MjU1M2MwOGIzNTQyMmY1ZDFmMDdjMzQzNWI0NjIiLCI1ODJmZTM5YmQzNTkwOWJhZjZjNDAzNjczNGUyMGY3NjYzOTFiYTgzNzI3ZmIxZDY4M2JlMDQ1ZmU0NTNiNWFmIiwiYWFjOWZiNDA0MjU4YzA2OWFlODUzODIzNjRmNWQyYmExZDQwNTE4YzZiMWY1NmFkZTZiYzIyZjMwMjhlYWZmMCJdLCJtb3VudHMiOltdLCJub19uZXdfcHJpdmlsZWdlcyI6dHJ1ZSwic2VjY29tcF9wcm9maWxlX3NoYTI1NiI6IiIsInNpZ25hbHMiOltdLCJ1c2VyIjp7Imdyb3VwX2lkbmFtZXMiOlt7InBhdHRlcm4iOiIiLCJzdHJhdGVneSI6ImFueSJ9XSwidW1hc2siOiIwMDIyIiwidXNlcl9pZG5hbWUiOnsicGF0dGVybiI6IiIsInN0cmF0ZWd5IjoiYW55In19LCJ3b3JraW5nX2RpciI6Ii8ifV0="
        aci_policy_str = self.aci_policy.get_serialized_output()
        
        self.assertEqual(aci_policy_str, expected_policy)


# @unittest.skip("not in use")
@pytest.mark.run(order=3)
class PolicyGeneratingImageInvalid(unittest.TestCase):
    def test_invalid_image_policy(self):

        policy = load_policy_from_image_name(
            "mcr.microsoft.com/aci/fake-image:master_20201210.2"
        )
        with self.assertRaises(SystemExit) as exc_info:
            policy.populate_policy_content_for_all_images(individual_image=True)
        self.assertEqual(exc_info.exception.code, 1)


# @unittest.skip("not in use")
@pytest.mark.run(order=4)
class PolicyGeneratingImageCleanRoom(unittest.TestCase):
    def test_clean_room_policy(self):
        client = docker.from_env()
        original_image = (
            "mcr.microsoft.com/aci/atlas-mount-azure-file-volume:master_20201210.2"
        )
        try:
            client.images.remove(original_image)
        except:
            # do nothing
            pass
        regular_image = load_policy_from_image_name(original_image)
        regular_image.populate_policy_content_for_all_images(individual_image=True)
        # create and tag same image to the new name to see if docker will error out that the image is not in a remote repo
        new_repo = "mcr.microsoft.com"
        new_image_name = "aci/atlas-mount-azure-file-volume"
        new_tag = "fake-tag"

        image = client.images.get(original_image)
        try:
            client.images.remove(new_repo + "/" + new_image_name + ":" + new_tag)
        except:
            # do nothing
            pass
        image.tag(new_repo + "/" + new_image_name, tag=new_tag)
        try:
            client.images.remove(original_image)
        except:
            # do nothing
            pass
        client.close()

        policy = load_policy_from_image_name(
            new_repo + "/" + new_image_name + ":" + new_tag
        )
        policy.populate_policy_content_for_all_images(individual_image=True)

        regular_image_json = json.loads(
            regular_image.get_serialized_output(output_type=OutputType.RAW, use_json=True)
        )

        clean_room_json = json.loads(
            policy.get_serialized_output(output_type=OutputType.RAW, use_json=True)
        )

        regular_image_json[config.POLICY_FIELD_CONTAINERS][
            config.POLICY_FIELD_CONTAINERS_ELEMENTS
        ]["0"].pop(config.POLICY_FIELD_CONTAINERS_ID)
        clean_room_json[config.POLICY_FIELD_CONTAINERS][
            config.POLICY_FIELD_CONTAINERS_ELEMENTS
        ]["0"].pop(config.POLICY_FIELD_CONTAINERS_ID)

        # see if the remote image and the local one produce the same output
        self.assertEqual(
            deepdiff.DeepDiff(regular_image_json, clean_room_json, ignore_order=True),
            {},
        )

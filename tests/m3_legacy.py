"""M3-PR1 executable oracle, copied from the measured M1 close.

Snapshot, policy and composed ownership source is verbatim below, including
imports, constants, decorators and definition-bound defaults. Supporting modules
are loaded from the SHA-authenticated local Git tree, never production globals.
There is no network fallback. Authentication precedes every comparison session.
"""
from __future__ import annotations

import ast
from contextlib import contextmanager
from functools import lru_cache
import hashlib
import importlib
import importlib.abc
import importlib.util
import linecache
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

MEASURED_SHA = '9dc1f85fc0e06cb58b73bad6d09da4c89ee9a4d6'
DESIGN_HEAD = '7c420a2d27ec73a347f2c2bc72d0564c730d7830'
ROOT = Path(__file__).resolve().parents[1]

SOURCE_SHA256 = {'src/receipt/__init__.py': '41537d613807c876cf8b13c21bb4ce63d1f2de6d0446d8b854bdd4ef32553d60',
 'src/receipt/_names.py': '502dddded965b9df6b6b82b497048620088966163acb9a2169008d9c35aca5b8',
 'src/receipt/_render.py': '9250c76fd725f19097e458c511c9c8765c30e6a33206707f3b6a747ac4cb7e09',
 'src/receipt/_unicode_repertoire.py': '82e4327f7936fb4816a5303c470f1fc7bd3e64bd4c100a1753a450344a049a3f',
 'src/receipt/append_gate.py': '3ff7cfb4211a3c06fef4c1d9a39592ff38010858f1f99b23b87ccf8fd620bda8',
 'src/receipt/attest.py': 'dd8f2b72237ef912ec8db299265780785e0617c46773db1b6f4d820a1bb40aef',
 'src/receipt/canonical.py': '562bf267b7686bce8cb71f3c13f34825c21cd4ef0aba1c0c46aff16962a6cadd',
 'src/receipt/cli.py': 'c19edfb6e20e7b5b1348176c41acf62744bc3b150aa8a9dfe5ec7b5b14d4e2ff',
 'src/receipt/corpus.py': '8019307eeb2075e7757ef9ad4de70fd61e3c3fe223c6f3e061699175577c181c',
 'src/receipt/protected_tree.py': '68e8890c2f9b37e887844442ba48242ceb198bdb424eff433857d7940828c812',
 'src/receipt/release_chain.py': 'c9c1fedc3e738ddf5eb3a8da5d67ee20e98ab3cb382a236a5cfe828ee4572ec6',
 'src/receipt/sign.py': 'd2801285f71492f73d2cc24face547b7f8ec52344e519fa0712142299af4245b',
 'src/receipt/snapshot.py': '51a15104354b2dfe7880ace6ee74b14908826118e2a43638e894e43999501148',
 'src/receipt/tsa.py': '47f7fecd7cc44c31b71a24f3c74a9fdb11507dafc5c28cc21b75b1db20dffa15',
 'src/receipt/verify.py': '2d58262fb981331582e03b7aab6a35e895e23470b57a376b88615fe965cad8c7'}

BODY_SHA256 = {'src/receipt/snapshot.py': {'assert_no_merging_entries': '66594ab1debe51cf53a25dd93b3fb02ebe43b180ce834db2b107597bf31ef571',
                             '_ancestor_shape_error': '957d420cefeb58c4ace1cc08ad123ae7a2414e7b6603306697c90b5182ca3963',
                             '_check_tree_ancestor': '293379d3f2354ecf097d350619061228db89875ca250c315a2be6900e6d39f4b',
                             '_tree_path_decode': 'b68500535019f1c3fc4e6e4d284a3cc17a0de7bee9487a3fcb42ed30cd4d777a',
                             '_tree_path_encode': '91317503a62e00f0732de9475b314cdaac35c377a1dd2046fa0c86e44507122d',
                             '_validate_expected_oid': '794adc327f01a9c7f670acdd1ff4eb3a4114cc08e3f883135cadce5b5a0de3cc',
                             '_WorkPool.root': '19e158e1b8cdb565807b1ddaab2ccf952d9739fdf14a6db0781381d7fc935d92',
                             '_RawTreeEntry.display_mode': 'e202b02d3da8cebd9e66edcb4de87fc8c481369d1eff52395a9695da6b5ee593',
                             '_RawTreeEntry.object_type': '087ce71d11e0f9a2afc549cdbe0f958ca47f796a6c3134000392a2ef01f67110',
                             '_git_environment': 'f8241e372810e1b894756d57e1ab69b8e8d93cf265aafe4589b3670a0f343f9d',
                             '_kill_reap_and_close': '97adcb93db67c32d814ebc3f301fa87a9b32d45192e88d19f9b84def9c3ea219',
                             '_bounded_process': 'b1045064ae6d3bfeeb12f8a201f491b2a64ea5c0bb1a03d86df780ce4965d59b',
                             '_bounded_process.drain': '3e3c811e811229eb2378f71c064d53ff948ccb2aec069c90965be05f0dc8be94',
                             '_git_run': '70b2ee4cf12e01473fb3703656e16ffa16ebd395d914b0f6fc50836c65de662f',
                             '_first_error': '62ad2dcf38a146698fc7745ff6a791a11a2bc7d8277305dac7eea874e94be12e',
                             '_object_arguments': '0bde78facc4ac8f5fbbf9816ad939deb7b95e18beb96ce4a5be2f0567c66fa43',
                             '_parse_version': 'a326cd715c37db9a7d5f19c79d6b887879f974de17091e25eae6788c8b5dcf00',
                             '_parse_config': '171061e797cae6d9d04fab66aadfacfb5a230f75ed7b3445c943100516f4e02e',
                             '_config_bool': '5a76600e6b272c4651eeb96fe7d95a328f8ce2edb9054bea3e7b982a289a95b7',
                             '_config_key_denied': 'dc3f7b8b473c2fd8d50824d117712e6c3b55c0612431d60751d4a2f3c2a46436',
                             '_audit_config': '070bfbb539848dfb5a6332b8b6f6194d32741dcdb0505e961bdbf35973c49d4e',
                             '_create_global_config': 'c166dc04409c43884707573e4f9440ba205ce60ec1df85bb74250c9bc55f081c',
                             '_raw_tree_sort_key': '91359a2483ccbf74704fb41fad2361347ee2e221bebc302a1cf344f1729917ce',
                             '_parse_raw_tree': '9e690470677fe0d1f111cfef2790447b2f86b79f2339601c7ae7dc6c65951d5e',
                             '_canonical_commit': 'aefc9a947d4c5456a45535f8bee7764200ac82f183ea3b89f1c4b10aa7dd9eda',
                             '_canonical_commit.object_name': 'b4a19182e28cb96b99a7dc22d95b357fd54d3f2049961c5f021637151156b43e',
                             '_canonical_commit.accept_header': 'bf43f1b9e5ca36b3931b6f9fd392da8068aad5f992e973212cd52ece49c6cc42',
                             '_unsupported_attribute': '3aaabd1da57cd890aef6e2b9a0fb195f6eadf187d20bb369dad362ab397142e5',
                             '_attribute_pattern': '7ae98e028890c3557beaece2d0baefe203d8adefad9abecdf2e694e879dabb18',
                             '_parse_attribute_file': '07bc3dc4d005ca383df99e1b8e8432235f8483d3d1e808e1147b5c426b392a96',
                             '_segment_matches': 'b7dafe61c398e8a1a7d1c3f4b1528908bc25ce31532ea925592183d7af407f27',
                             '_attribute_matches': '518690c253ae42ac6cf8c054f4b3f1b29211513d94fd7fc75a7015fb1bf63fb4',
                             '_BatchReader.__init__': '9bdcb75a26c14048911e79ee3dc532228d2747f8ebb6f2cdd42fc347cedae3ab',
                             '_BatchReader._drain_stderr': '250918e932a402086f7127a5029dcbe6f47611a9f9e87b0ecfe8be0f558997bc',
                             '_BatchReader.abandoned': 'be77a6478dfe5146a048bf7c2e21df91919175674a1bcd54b6017223b011c444',
                             '_BatchReader.process': '59c8f6a56dcf3b42bcf295abb8781210e84106eb0e673d72dc1843a547895e8c',
                             '_BatchReader._usable': 'bc5025a58ff8e7609677f5313200773d1f12f00b163510be6add731f4b956cf4',
                             '_BatchReader.abandon': '5bfba61ba9fb3281cc5f681e79d1e4162a034b5e3435fd9aa823b4676154a61e',
                             '_BatchReader._request': 'a7e241066433e35dd1e906b7c21eb75845823a63742bcc8af7bbdabb3dd66b07',
                             '_BatchReader._read_with_deadline': '1b34623b7447bcb391d3461e7e628e1d74ff738873ab61a3c35aebfbc97c7761',
                             '_BatchReader._read_with_deadline.read': 'ec24a376d6b3d626c442986de02789516dbff05cbb7bcc2499d4110655b4d375',
                             '_BatchReader._line': '494ca9b24eaddb00daeccbaa859270edba11685d3eff20f06c42cac944025430',
                             '_BatchReader._parse_header': '8cb7f82d762930eb0ff766b9edea23b3c9337fda020b7b415b8d85298a2ed01b',
                             '_BatchReader.info': '67ab8c16de962b1565284e97686bb143bc647b708923de88eb88fcea2aba25dd',
                             '_BatchReader.consume': '1ec6768ba0134b6d65dd62485b3e84f8d9b568af5ddcf2d3f025dd6d6162b477',
                             '_BatchReader.close': '07796657209eeff31824035127f91f1e39987260c41a45028d0f392f7d914244',
                             '_BatchReader.close.kill': 'cca83bc7f19ab5c2acb739a52225c1f48f62eb0238eab1656da2a4c11993bcc1',
                             '_BatchReader.close.wait': '774ea74e018548c8b2d5c7a9b33b93ce7dd4651a70e37aa535537ff8e51410f9',
                             '_BatchReader.__enter__': 'ef2c88fd15c135b6ad9c8287bec1f1685891e59a95a778628c6088a317f116e7',
                             '_BatchReader.__exit__': 'c77e63e90331984d07ae2b292c507b0c3a514a85a8e72bc5d18fddaf3354542a',
                             'TreeListing.tree_oid': '26253a27ee8670d3cb3d6bb03dc8be65acc0fe17a581ff0f2213a2ad27b5bd54',
                             'TreeListing._walk_from': '5bcaf48f5e14ed55fdef2b82a35babf9285b8641d88424d6fe49baf85ece7f27',
                             'TreeListing._walk': 'a9f468e083663aa5a2cd92ac9ea4768803ddabf52b0ceeba529d8a6c21395ba9',
                             'TreeListing.iter_entries': 'e4c9d26c188d53d47bf3ba1da54c9c6d896a4ede029cdf3c5867047d9af47900',
                             'TreeListing.__iter__': 'f2a21cac944feb57e942a60acaa6b80886fa8bee407347f1bb72c88bf663a549',
                             'TreeListing.__len__': '32d90aca91e45d1fd36c78a6763214e212dccc8c81977535b8a1acf9bca81d68',
                             'TreeListing.children': '26a1b4f0adfe61cbd2482211fc883b1546a5d42479632b73b4800a7970a27803',
                             'TreeListing.as_dict': '4c5ce6dc8a07d09f29c3881539653c9765d26c4afe0df0235d082a8e9108e029',
                             '_DigestIterator.__init__': 'b0976f42a7af54234c55ac399442bbd3c3bbdd668c009c97a8282c8f2674cf2e',
                             '_DigestIterator.__iter__': '5e4f5f005107200e6b40339aaaa0eccb7dcc7a5efef5fb8a9f4959a4ea2c023c',
                             '_DigestIterator.__next__': '67eafda526162c9f4aaab667579e6e299e4b99b72fe6b9ee480a086c39738e9e',
                             '_DigestIterator.__next__.consume': '17705a2c43591e358181db0198b0cca84dc42a0c0622ba7374054828bf27c6e5',
                             '_DigestIterator.close': '22ea06bbf464f10a55c559a9c3c3ed79bf0ae9fc31a731b286e86a5369b03cea',
                             '_DigestIterator.__del__': '74701d639c50b5de0dc288334552d8d118536173f395c421116babfc38d8a34d',
                             'TreeSnapshot.select': 'a9bb789c10a6473c1a0cdea6fe27840878ec7de49fa302656cec8333bbf870fb',
                             'TreeSnapshot._repository_directories': 'a7ea8f74e5ad0ab07ef49ee98dfb754fa7c45aab6157e18192cd43f4b7257f97',
                             'TreeSnapshot._repository_control_exists': 'f8e8d3be7cd77282bacaae54440923f08bc09c84cabe7acfca9cc9e7d1fb6e2e',
                             'TreeSnapshot._refuse_grafts_and_shallow': '7c989a702eac5110d3ed0b7ae89d7d089a60451d7a85558afedf32d51a57a48a',
                             'TreeSnapshot._refuse_alternates': 'fe45e48540149d4a8ee7add0dd834f0e0fcf8e9fcc4c2ed2cab14fd9f13e7c70',
                             'TreeSnapshot._reaudit_repository_files': '5a612207cf4a31aab860b7b50e84a009b8996fdf8a96fe217128c6b77c4c56b6',
                             'TreeSnapshot.__enter__': 'a6d5a9a2c8ca0a16b10324ae2fc3172037eedb468e7ff0af42b71cfdd7df09ab',
                             'TreeSnapshot.__exit__': '9501846792072e166928d381363e83c73a811afc61c9b558b238095f1ea76edd',
                             'TreeSnapshot.root': '6304b88f0f0c8632595f3725fcd8333f17b74a73bdff9b7540b5afa13b1712e6',
                             'TreeSnapshot.common_dir': 'fdb4e9f843bbd9c5dc9fdcdfb53c3895ff3102d1ed6c9e55e5e38c18c330a4d6',
                             'TreeSnapshot.work': 'c432c702cd6283163b57957ad54817fe56c5403310192ea0ceb4f8d70ffad01b',
                             'TreeSnapshot._verification_total': '2c299681d70a91909fac8233cc732a5c7f9eb518cb49eee59acfc53d26112272',
                             'TreeSnapshot._charge_verification': '0cd9b99e9416c41ae9b1714e4b65f6aa1c080e21eadfaee3f0d70310edca98a9',
                             'TreeSnapshot._link_verification_work': 'c61222fdb959dbf27106926e864364e923de6f64d47bed2acd32db066a207b83',
                             'TreeSnapshot.batch_pid': 'a059f8f2b89a4053dad17ab4286f9d2f8ae38696118e562ea5cce5b6c539e23f',
                             'TreeSnapshot.temporary_directory': '59f9fc44fefe816b4ff589272c63dfbe49fa1e76120ae86d6e7a4902b03a4c17',
                             'TreeSnapshot._batch': '64a48d046d93bb03da70cdf864846f6454f69b7d8d83096c687f9da6d5c09e21',
                             'TreeSnapshot._abandon': '8e494fe85f1ea2218600b36e819a6505310c7f36bf1bbf968b3b620b696f9464',
                             'TreeSnapshot._validate_oid': 'aaf14933bce2d6f8d0f9af65d324c95a135e8c2bca97c8a405aa70df58de50f9',
                             'TreeSnapshot._require_entry': 'c2904a9d24484227570561b6c8277de65eb8e93c9e826a0f4ea6efe23cedbf49',
                             'TreeSnapshot.header': '73fb70c5d3ecf0c4d9173a17a20080d7d217305c4f9d80b9ae0f77c58b3694f0',
                             'TreeSnapshot._charge_tree_object': '6cf7e0f7640caa5f7cc715865bb151a828af21dd958b277f6aa6fa35d8fb6d07',
                             'TreeSnapshot._tree_object': 'd8a16737161d8cfa8a038fddc54d465caaef0369cf290f9fb71b13117c77f422',
                             'TreeSnapshot._commit_object': '5a242c836124586dad0b20b45614f52221fefd468469938254fe9339e237aee1',
                             'TreeSnapshot._charge_walk_records': 'cea81c6fd7dc433407cd389c20a510d93f61a191b625e5c6e596c4254c56d306',
                             'TreeSnapshot._find_raw_entry': 'a68ddee5167256bd4d2e7b46eed934422a9755175bdb578346ee6d9dc0c34817',
                             'TreeSnapshot._path_parts': '69b44ae8cbf029a8d06845d556690f63dc4373a23bbb1a5172a61bdd4b26fbf7',
                             'TreeSnapshot._public_entry': '9789f829865c76a8da25e273f00b76e684855e2f78a56d050932ef8da3d00ff7',
                             'TreeSnapshot._charge_path_bytes': '5fafae109b966d61c07a92b43e6449aea954b94e8706687df1ee22cd5aa80eb8',
                             'TreeSnapshot._build_listing': '664dde3bab99d4bd81b2a84b097fd1a7cea33a87a91fd5442c10a0f7abecaa09',
                             'TreeSnapshot.entry': 'e0d29820d23e2d412c8578f5917d71c5028bb5b2082b46020e129bccde2c1f8c',
                             'TreeSnapshot.entries': 'd48adb82effdced344562268e0b880c5b6a7ceca3d8e01073826f85153d7452f',
                             'TreeSnapshot.blob': '742c05ec070a0eaad71df5b56cfc93b19a8b3683d5859bcce28248edd23ed314',
                             'TreeSnapshot.digests': '4478b13d9ab8c5e44464017578c5acf0ba5de4ad9d11e8bffd69d22ba296393c',
                             'TreeSnapshot.changed_paths': 'c0eb20408542408d83e779595f7990e72dc683d76298d6a6fd0fa363142783ca',
                             'TreeSnapshot.parents': 'f2cea19756ef2e50c2d2ca9975412a1bacb2ee48f7a83da7f5c3623a2a5eed25',
                             'TreeSnapshot.assert_ancestor': '5e2e5bb7bf6b397aa8c0e4a613d7df980705a00a028e3ae9b90330b4fc264332',
                             'TreeSnapshot.verify_object_store': '5297c587b4702a3667c15372cdda9efb0b6ce5de50eb54117a2ab9418c664916',
                             'TreeSnapshot._raw_entry_at': 'f6400da47f621fdef5ecad1385cb827b3cbf01fbee84d4f619ff282dfa741efa',
                             'TreeSnapshot._attribute_rules': '3cb50f40ec1d5ac988b83ce800bf280a246ce3ee6fbad982d9e9375d1c3ad192',
                             'TreeSnapshot._attribute_step': '5daafc8a1c329764c2b7440c8632a7737593279dd6b61bf01327d350565fb820',
                             'TreeSnapshot.refuse_transforming_attributes': 'ec84c03d9ec83629f46c764cb46a1cde2476aec38befd727214e1202eec49b2b',
                             'TreeSnapshot.materialize': '045fb4b03df8fcee718e0dd027545b7e701ef2813c58f9c90a8d96866e9b9d9c',
                             'Materialization.__init__': '79f1849f093b4127ae3439b2995a7fa4d06b619cbdeb668da75339e635ed6695',
                             'Materialization.path': 'f97741e5d31890af73114d1a1f7d7beab21d2a5d19666d0aea5c9a7dbbff80e5',
                             'Materialization.entries': '99611d665c43798881fb1adb3d0c3c6de628821e98417e7add6b5331cd6961e3',
                             'Materialization._deduplicated_prefixes': 'd9aa959a936dce6e493c42490259d74cc1ea4d333b05209cd5c6d61f0a18f9a6',
                             'Materialization._export_error': '21a9a12dfdd575f0da369ea69a5b05cf6d6474e7ae9254c54fe40222629edf07',
                             'Materialization._selected_entries': '322fe8d7a37f2737aaba5a322ee8cafe37dab61f0e3ec1e5ffe1d529a8101785',
                             'Materialization._write_chunk': 'b13e963d78d8e66340e5f7d2ee4a71575663895afb940c5fecf3e12f9a28a37e',
                             'Materialization.__enter__': '9ad1092069e4023a6624c306ba9c4fc553a822a04ce6622d364b655f65586457',
                             'Materialization.__exit__': '9d23713e3d6ec9d77a018c74d0ee67ea1238768398009a27da73c41784622854',
                             'Materialization._exact_filename': 'ac4c949b2d49b6adde1a15332f2216322fb7602723345a020c56d83b9175d40e',
                             'Materialization.anchor_set_sha256': 'd7298662d9cda73bbcf2eebcf42cdf110ae3e79c58f4031421d64f0dbbb7261c'},
 'src/receipt/protected_tree.py': {'_paths': 'cc0ddb2b59f84ae1a0359267e7365da3097097c092ef260da79025348572f5ef',
                                   'ProtectionPlan.__post_init__': '7195a6f605fd5d330cf699184d61e7b548e35b0e1be0919d6f6134d747680d3b',
                                   'ProtectionPlan.chain_names': '2888c05ff32c0948d73c8b0c66e910f80bf85c9babc5263f2ef48b96d6b10e3f',
                                   'ProtectionPlan.materialization': '894928323537f273a5b4dbcf8784dd9a269847ec3397b01e0b0fa2d63d9a07ba',
                                   'ProtectionPlan.fingerprint': '0f70aa7898dceb081b00413289468d0ea9597a1f3e4b573b69354cafd40c1717',
                                   'ModeFact.regular': 'dec359cdc61499410651030774f372c1ce91dedbbba9fbae442c65bf1f927e36',
                                   'ModeFact.directory': '33f550b15b9e647b44ed607f9d89c569184b8a1e3f7c107c35e1139510be13f7',
                                   'ModeFact.finding': 'f6e068fd2f43f4cdee2c90a7c4eb0f50968526cb5d165fe1d77cfece62183503',
                                   'classify_mode': '329a26b4505db2bd42915088b93450d2be487fd78455de61101234c86e22b480',
                                   'ancestor_finding': '5a187671b4075d1518404d1f4e1ece8bd4af925871c5f96098bf5624efb4128c',
                                   '_ShapeFacts.__init__': '24a710d7273a6ed9ee1c253c7b66d555f3bd7b7d79f13af85f59d1f9818a7bfd',
                                   '_ShapeFacts.work': 'a42e556ca96ddd17299ceb753003828152cf67112940ae188c5d76da1bf87d85',
                                   '_ShapeFacts.mode': '05f14f947f5d9573110390590d4e5c658fe6bd6f2f8e84648b95f7cde5c965d1',
                                   '_ShapeFacts.metadata': '5ade94a7965b79fe5f74c9c6fb5d3b76c2bb0a97a084d5808eff5e9b695676b8',
                                   '_ShapeFacts.ancestor': '9b68a8233cccd9b2b6f2bf4380b9cac54db697a2af029f716f1b8aec7e8c6848',
                                   'regular_entries': '9e70c8340413cee5606a49356c6e86f0c38d7706ff4f072b810458d2f74dc908',
                                   'export_prefixes': 'c6284f6a43fa514671a725b8bd8fdd34ad00be72e188b08a4d488b7c78a0596a',
                                   '_Refusal.__init__': '794af3cb5b66c9bc4188df6ee199defd30f2cfe603ffbeb99b626113256f0db5',
                                   '_SiblingCollision.__init__': 'f7a256886b59fb50f2306a6eb5447861c06b44dc4e055f07c431f03f6c0915ec',
                                   '_AliasNode.match': '78ffb67e91a0bd3fb09000647684656806123744adb2dfb0b8b8368330cbb61f',
                                   '_AliasNode.add': 'ea39eef681f88a9e74f563bacca6e2530f11cd6a18d615a2b8480694bb656c6c',
                                   '_AliasNode.alias': '0a78c99dc97a792376e63861a0ef61bc387d12a74d7b1f4e4901b5ff47008573',
                                   '_NameFacts.__init__': 'fe263a1bbe7e97c2b485194738283f2744cb77ffda73bdcbaa26a4a14159d0fa',
                                   '_NameFacts.work': '8cc98f34828e4108bd72ae75da61e6f3e8db7c7e760389c63b7a014ee42d2066',
                                   '_NameFacts.fold': '0d9b6f09d31487f82ca4acbb1254c7cef2ef2edd590d444fec6d16073fe71b3c',
                                   '_NameFacts.folded_parts': '6b779ed361f91add323c12373f50ffc512e59e2c8b5d221c28b8b3c31d1d4fc0',
                                   '_NameFacts.full_fold': '422220da1b46eb9ef0413eaf8eb7bceee45c9cab012388a255abab403094dea3',
                                   '_NameFacts.carries_suffix': 'e4ec064339308a4354ba42c088c99ba0c9175ccb68c3c368e4663281b679f04e',
                                   '_NameFacts.short_suffix': '0f0d37231023844d6a8671ab2161fbcbd85429200b74ceff1834193b5139ac47',
                                   '_NameFacts.path_fold': '6928128f841a9688bdd4e308b42b73e004f06fba3f7fecbb910b34c894b8651a',
                                   '_NameFacts.primitive': '9c77671eb52ddc3890c9be05716f90725311c3ad725f0e0cc715a41d97884fd5',
                                   '_NameFacts.aliases': 'daba81b5a31cf8b7f6ec10c31fe6fdc7e4d735b75fa711b3b53a7c94970b9e16',
                                   '_NameFacts.in_roots': 'e15304288a0b34742712fad92a315c0f3801133dd99086681a5077a83d6ff4aa',
                                   '_NameFacts.scoped': '3e8745e9e0b8e8b93224fdce94363ccda19e4a258ef45f55105d15276619ea9d',
                                   '_NameFacts.names': '852776474537a5d953f5f3180f3e23ef32bd72d43a14285d3c53e13e9071b460',
                                   '_NameFacts.siblings': '1854262a4e720323c29e615f0b9bd7936e5768511b901f2ed43777a087942ea5',
                                   '_NameFacts.siblings.counted_names': '4e22418447e06c1f7d7dfcd992d810f828c23b148d41dc8747a617b90c881d09',
                                   '_NameFacts.sibling_paths': 'd4cd3621fd820f27833ef3721746a18a3c469ceeee8a041290aa2b5e151f736a',
                                   '_NameFacts.suffixes': '4f3225330e97b100f1cc6d38886a6c8b98b5c7916011a9839617e67bd43bb875',
                                   'index_children': '05795c18f92e730d149b176a7a1e3812599341f9d9d4cb6f9d98182a30b3c2c8',
                                   '_NameRun.__init__': '6d4a508a4777c29f9390da0c89159821fd1ad04d27ce8094658183cf6eab76bc',
                                   '_NameRun.evaluate': '7b326b0462a677ffef6482e8e352a69174812ab558c39d868f7b737b9e056b0f',
                                   '_NameRun.binding': '34753be647ef0b5fdceb8e33847f284e5d99d757804f8bdeac64729630d012da',
                                   'evaluate_binding_mapping': 'd5d9e24ad21dd400d2a150163a5e939fa35de4da32ad05139f280ec8679345ad',
                                   'folded_path_index': '37474ebfa67b7b93caeeeb7538420e71a36b07db83574fbb631d06ee4efabf90',
                                   'read_binding_listing': 'b3200e991ac2c690fced9924b8d23f0fa25842d44f128c116775fc4815e31376',
                                   'has_folded_suffix': '51ab6db23acdb2854468ecb1e7148c4c670b4b862d0ae30f0408de304b21f4d1',
                                   'folded_parts': 'ae51bf14caf9fd73f65b9ef19d8a49d8cb45eece905f96d62fc672eb12e4a4d0',
                                   'evaluate_name_mapping': '9958a48a99715e7a984c5c38bbe48fd80bf100324f50286441b2b623556a7c00',
                                   'screen_siblings': 'd02969b6db59a422e40f2952d59f2e4430add2f1339857035e82837f87c530fb',
                                   'DeclarationObligations.__post_init__': '7b335f1afeb5e49e7c7ef4d791f2f8b728cea91a8b140cb17e81af0441a2c2f2',
                                   'evaluate_declarations': 'e76823154b8531a28f1c8cb4e5f0572ae5b856f45dec582320e52eedcdffcf25',
                                   '_unsupported_attribute': 'c941e5882fb669d509b958d9f47da6fbf92a5ab556aece2dd5e4b68cda65496d',
                                   '_attribute_pattern': 'ccc87b81089ec30748f81fce99a9eda599d46ed9f369806097c6681bb229395b',
                                   '_parse_attribute_file': 'a7460c81f2c26276220928339367fcf6af3ba97e87493d2bdd109a1e942a3f49',
                                   '_segment_matches': '00c5b18ab3b52d136e3b175af9618d5edb7f97a104ba28edfbf672f3d043eeb9',
                                   '_attribute_matches': 'd9fb4ca563f44b40778b24dbbe45166c4adb613dadd4fb6dd9061ec1a0dbb2d4',
                                   'load_attribute_rules': '97a0e3d97cd6b5c2db701f122394b71c0aa4d277dbc5f67e36b73d8997698464',
                                   'AttributeOutcome.finding': 'ebe0d1bc18b2f9addce8168bd847d2418ef17c50b903f4d9f67e5f6b2d640fe9',
                                   '_fold_attribute_path': 'e39d95a44495afce638b116dc4db59e5ea5a4e7c6a67beb0982facd73a898d6b',
                                   '_AttributeStore.__init__': '0a4f1299a7e364a79f14f96d3318660e036a3a73112cd213e9f953b51c58ce22',
                                   '_AttributeStore.merge': 'a2f5ba38c7b6ad0f354788d2506d0f6d8f417a04fabeb4766a6e250a09ae0e3e',
                                   '_AttributeStore.work': '4ae6553c93bb29e4f3cbdf18fd2a56083c83386972b154f393b39adaf03cf0f4',
                                   '_AttributeStore.folded_path': '6e05004a6b0d0ee56f1e5fbb7ecad74a53771660c8b7ba4ce46430abe8967d26',
                                   '_AttributeStore.rule': '97af84caeeb83a5c8de76e2c4f4741f6ffb9c0ecf4bd871805fdea0ca2ba0ce5',
                                   '_AttributeStore.rule.step': 'cbd5bd4d9dde5fc85079eb70444a92f5e169dd6bdbef6d31d8dae89ea910953b',
                                   '_attribute_store': '7c6e1706b3ebcffccc0d68a689a0db029c0d38f5092b5690dce0ac3bb6e5115d',
                                   '_charge_attribute_work': '7a8d20878cf298835a3e9ad8c35a0d89ae702408c4d856679389bf09840670ab',
                                   '_admit_attribute_paths': 'f454f53e592a45333ef8a9c57893941b3b0ed266a305fde91c9375a6278f6b30',
                                   'attribute_error': '41bbe4fbc1b2dceaaf4f29ad20fcd167b07f54800d314f43958fc5dde60803c5',
                                   'refuse_attributes': 'a0589da396f75def5218c8bc397fc84838b7fb9de027a0dbfde78f5481b92643',
                                   'TreePolicy.__post_init__': '2e693626ae6eaaedfd99077c1883b2985d7b9c0136cf34ad0f5720205f532995',
                                   'TreePolicy.subject': '22ad8cb557c1bb1b1e7e4343c1deee87ddf2ad6ac3134f06b2c02542fd387649',
                                   'TreePolicy.name_work': 'baa18fef6b5c739f3e47dbaf60077955da66ef6f77e3cc51deb9cb320210a6b4',
                                   'TreePolicy.shape_work': '43e8dd9f2c45d21695077f3290389b6ab78ea343b75599f0344a56e315315620',
                                   'TreePolicy.attribute_work': '34bb8baddcc449c001d99c30ace6fbc7bd3fc845d778404256273bfe7274e123',
                                   'TreePolicy.export_work': 'bf81f7c41531a357487c9f2679025e570f4ab9cd3fef52d9b522f36ede5ba4ac',
                                   'TreePolicy._read_export': '70cd9b774913ae6cda09e6c568ef241b78b4d7a0589a995f0da964db409eaf43',
                                   'TreePolicy._read_export.remember': '9f7e6c4db1373bf2fa987af92eec3ea0009e9d779d0b4a24c583d055ae2bdf83',
                                   'TreePolicy._read_export.topology': '25cb5b8d3bb9984d748eb6751e428edc57c5e568cb6679ca6364cfae5e7763c2',
                                   'TreePolicy._read_export.add': 'e130fad5c2051a474c0698869477d7ecd9191ece469ba02c72f9db0d4f4dd9d8',
                                   'TreePolicy._export_names': '68c85abcae6a52590ea71e8a7e710e8221c764ae6840849234f8f6660df1552c',
                                   'TreePolicy.regular_entries': '9ea23e9d5a316df382f200933e8688299d961449c10cdcafb2fc98e275f25f8e',
                                   'TreePolicy.manifest_children': '8cd541df72629a2a875a8335e5adf70b148ec2d767aa27ae94431c32b34ed5ac',
                                   'TreePolicy.manifest_initialized': '96edaa9fcc5f6f6e2520945588e7d18ae83c85e151f90e7a796be7cc40c5302e',
                                   'TreePolicy.materialize': 'fc192003c4209cb5210fc5b68482d1221790c19f2593a471885044d40c027458',
                                   'TreePolicy.observe_entries': 'e3ef993b354a6b55789c5911ea0b5ad71e405641173ba22da1c631b3384354c0',
                                   'TreePolicy.read_listing': 'abcb2060baba4d9e13f1ab5418e8cb805740ebc41f1d0fc2a2c8a60c57b0b905',
                                   'TreePolicy._validate_view': '1b7884fabb606b7f06fc1bb536a8a1f5f37043bdf52d4007e9ff98e2e371fa97',
                                   'TreePolicy.evaluate': '122f11b8583cde7548046e89367cc71db6125cfbcfcc357c93b754aa4612fd4f',
                                   'TreePolicy._view': 'd9e97a8392b7dedda6156d0b8a493d5e965f2ddefc8609e2c362c50f53c53b37',
                                   'TreePolicy.evaluate_modes': '63d0c84a5cb6172b40c569f82fa8400f2ee89d8e94f30cde69f39a939f54ab0f',
                                   'TreePolicy.evaluate_ancestors': 'ff6d1be8e3031a6abb6582d01e84fba4bfff11eca7537b1b39cb5b89266add22',
                                   'TreePolicy.select_export': '1c6f5e6d707859d16434a69e68e16fdc8114dcd94c3a0031bafae2d217b5315a',
                                   'TreePolicy.evaluate_attributes': 'e7da06ed5cc82a7318b0ddf49da944b2e23800fc824c5951d6554da2c38a222d',
                                   'ProtectedTreeView.plan_fingerprint': 'aebfaf52bdb52c84733a970e50ebcb11e2d735178697964e4c1e863fb7e5f825',
                                   'ProtectedTreeView.finding_for': 'c50a57fc7228b1910f002dbe8e8553011b64a557b049d570d6dbd617e10eb116',
                                   'ProtectedTreeView.require': 'c30e660ea5f4150d57d4c551c7ae32bbffc2e6ef1056a8c53e11571a3452fbbe',
                                   'ProtectedSelection.entries_for': 'd49cef83fffb20cb92c0f21587919cbd3e42914260699ab9db33002110b1885c',
                                   'DirectoryEvidence.__post_init__': '2434dfc88e53022fefad0bbcda8d7e9a74024fe9205a073aa11b0c1ef4c67fbd',
                                   '_PolicyMaterialization.__init__': 'e4cb9a8732f65d10fb81d22ba6a8d4d5a3049190708dab5585809f59b0ca0a7a',
                                   '_PolicyMaterialization._selected_entries': 'fcba1bbf297a4c6a86be2cd7933059469721daaa15f5252a672e1c2db9300b2b'},
 'src/receipt/verify.py': {'_custody_state_error': '249c33f7b7fc8e01aeb0ce8311385f174384269f5a28f542616bd9127f969aea',
                           '_exception_detail': '6d6c90815a070858ee95aa6fe55780e7ebfe0418cb80b25a7e6b910e0f9bd79e',
                           'VerificationSpec.__post_init__': '542f21c0c37e6dc469afe23fbc90ccf893bfd1bf77d201ed7304a659036d6372',
                           'LoadedSpec.__new__': '92912f3a0cc28e38bc24ae2adb123fbcf42537150db9bf27cfac14775ce36319',
                           'VerifyResult.ok': '436553553bcbf4e91a5263701e1c619d73eb3a481cddf97884fd3c6b2ba1cfb5',
                           'VerifyResult.head_name': '3fe4e963a84303175e1e0f27703bee0bf14e052e10ca6464c018c49a93efb666',
                           'VerifyResult.anchor_set_sha256': '5ec9158b89331346eb121d79f10c6c3d744f84fbf962b053dd5288f953d9c3fc',
                           'VerifyResult.anchor_file_sha256s': '48ba2645688556e4a79ffc4bd88b1b996e34a18dcccc84ec087d21a167f5afd6',
                           'VerifyResult.witness_times': 'aedf445fea44b633afaeb963c4c2c7b8f3bff9d1a54ecb5db1160c6a8bd0e25d',
                           'load_spec': 'e1c5a320d1a279b3de81b40076c183dc9620ddeacc59cce1f001aab6169b36f6',
                           '_witness_time': 'abdef50d003f93340c7864e585b3870df709b100e3fa17f6135309fbecbcfe25',
                           '_custody_detail': 'a86509a6827f5c98066b0ca56febf51faebfe9da49c6b032957b76d703037eea',
                           '_binding_detail': '5163e5e450eff3438ba794519d26835a160d378112ec57149c05fac13ae90af4',
                           '_declaration_detail': '04acd40cc09fa1081e696ee19e9b8775d331551ec97588f9ce8c429a92788bca',
                           'run_verification': '58bfb1122f2d1f98a5b74914774c5bf561ba51a40f4c48ba7d995e53f4ee2ce3',
                           'run_verification.result': '3f221c03de6177bdfdcffc1a5f8dbe5c759bc59a3ac729d1f894dbbf90d6cba7',
                           'run_verification.failed': '75704efb326acff7e55f8c065b84efb45d3ab012012fb6c93a938ee725f666bd',
                           'result_to_dict': 'b3a51f5fd5241e1ac54b4553e997c366dfdfc300706c272cd908e04258548652',
                           'result_to_dict.established_claim': '4b33541f0b5ea2cec2de17709c41954d5ae1ac06a5b5877b2d7e66e5b094499c'}}

FROZEN_SOURCE = {}

# BEGIN verbatim 9dc1f85fc0e06cb58b73bad6d09da4c89ee9a4d6:src/receipt/snapshot.py
FROZEN_SOURCE['src/receipt/snapshot.py'] = r'''"""Read and authenticate one immutable Git tree without consulting a checkout.

``TreeSnapshot`` selects a commit, parses canonical commit and raw tree
objects, and authenticates every fetched payload as
``<type> <size>\0<payload>``. A named object is type-bound before its payload
is used. Gitlinks are the sole exception: mode ``160000`` records a foreign
commit name, is never fetched, and need not exist locally. An unrelated blob
which a caller never reads is name- and type-bound by a tree walk, but this
module makes no claim about that blob's bytes.

The working tree and index are never subjects of this reader. The private
configuration setup and Git version children are not repository-addressed and
run from their own private temporary directories, never the caller's cwd.
Discovery uses the worktree only to establish that ``root`` is the repository
top level; every object operation thereafter carries an absolute ``--git-dir``
and ``--no-replace-objects``. All inherited ``GIT_*`` variables are discarded,
the three variables in :func:`_git_environment` are installed, and ``HOME`` is
deliberately preserved. Repository configuration is audited without includes
at selection and again at close. A same-owner configuration writer is not
excluded, but changed configuration or repository-control sentinel files are
rechecked at child boundaries and refused. A writer racing between one check
and the following system call remains a same-owner residual.

The configuration audit is scoped to the frozen :data:`GIT_COMMANDS`: private
``safe.directory`` setup; version, repository discovery, and configuration
listing; explicit revision resolution and the batch child; and the optional
object count and ``fsck``. Includes, program-valued keys, partial-clone and
promisor keys, and every family that can weaken ``fsck`` are denied in local
or worktree scope. Repository configuration never selects attribute or name
policy; malformed values can still refuse during discovery or the audit.
Adding a command requires revisiting the configuration boundary.

The default SHA-1 rehash closes substitution only to ordinary SHA-1 collision
resistance. :meth:`TreeSnapshot.verify_object_store` widens the subject from
the selected trees to the whole primary object database and asks Git's SHA1DC
``fsck`` to examine it. Git's own memory use during that command remains
Git's. Alternates are refused, so the primary database is the entire store.
SHA-256 repositories fail closed until a commit/tree/blob/corruption fixture
exists. Bare repositories, worktree snapshots, and index snapshots are not
supported.

Resource budgets are constants rather than input-derived guesses:

Candidate and base snapshots join one verification budget when they are
compared or ancestry is proved with the base snapshot object. Tree-object
bytes remain per snapshot as specified; path, attribute, content, and
materialization totals are then enforced across both snapshots together.

* ``MAX_TREE_ENTRIES`` is 1,048,576 entries per walk, versus 15,216 measured
  rulespec-us blobs, and bounds traversal and whole-tree alias work.
* ``MAX_TREE_OBJECT_BYTES`` is 64 MiB per commit or tree, checked from ``info``
  before payload bytes move. ``MAX_TREE_BYTES_TOTAL`` is 512 MiB of commit and
  tree payloads per snapshot; rulespec-us has 2,597 commits.
* ``MAX_ENTRY_NAME_BYTES`` and ``MAX_PATH_BYTES`` are each 4,096 bytes.
  ``MAX_PATH_BYTES_TOTAL`` is 256 MiB across paths built on demand. Listings
  are hierarchical so a long prefix is stored once rather than per leaf.
* ``MAX_GIT_OUTPUT_BYTES`` is 1 MiB for every non-batch, non-fsck Git call.
  ``MAX_GIT_SECONDS`` is 60 seconds for those calls and each batch response
  and graceful close. ``BATCH_KILL_REAP_SECONDS`` gives a killed batch child a
  fresh 5 seconds to be reaped after that graceful-close budget is spent.
* ``MAX_TREE_DEPTH`` is 256 and ``MAX_ANCESTRY_COMMITS`` is 1,048,576,
  bounding hostile nesting and parent walks while remaining above real trees.
* ``MAX_ATTRIBUTE_BYTES`` is 1 MiB per attributes file;
  ``MAX_ATTRIBUTE_BYTES_TOTAL`` is 16 MiB and
  ``MAX_ATTRIBUTE_RULES_TOTAL`` is 65,536 per verification.
  ``MAX_ATTRIBUTE_STATES_PER_LINE`` is 256; Git has no corresponding limit,
  but this bounds one matching rule's application fan-out and is far above
  Chronicle's maximum of three expanded states on one line.
  ``MAX_ATTRIBUTE_MATCH_WORK`` is 67,108,864 matcher transitions and applied
  states. Checks cover protected paths only, making this generous for
  Chronicle's small surface.
  Git 2.53.0 skips blank and comment lines before any other test, discards
  rule lines at least 2,048 bytes long and rules naming an invalid or
  reserved attribute, and stops reading a blob at an embedded NUL; this
  reader skips the same lines and refuses each discarding case and the NUL,
  so discarded input cannot silently change rule precedence.
* ``MAX_CONTENT_BLOB_BYTES`` is 256 MiB per streamed content object and
  ``MAX_CONTENT_BYTES_TOTAL`` is 16 GiB. The largest measured rulespec-us blob
  is 6,550,684 bytes and all 15,216 blobs total 107,132,889 bytes.
* ``MAX_MATERIALIZED_BLOB_BYTES`` is 64 MiB because downstream manifest and
  signature readers hold a file whole. ``MAX_MATERIALIZED_BYTES`` is 4 GiB,
  charged for every byte written into the private directory.
* ``MAX_FSCK_OBJECTS`` is 4,194,304 and ``MAX_STORE_KIB`` is 16 GiB expressed
  as 16,777,216 KiB, versus 79,890 measured rulespec-us objects.
  ``MAX_FSCK_OUTPUT_BYTES`` is 1 MiB and ``MAX_FSCK_SECONDS`` is 600 seconds.

Git 2.36.0 is the reader floor because it introduced ``cat-file
--batch-command``. The frozen ``fsck --no-references`` invocation was added
to Git in 2.50.0; optional store verification therefore fails closed on 2.36
through 2.49 instead of pretending that option exists. This resolves an
inconsistency in the frozen plan without weakening either command.

Where the plan fixes no refusal text or representation detail, this module
fails closed: malformed protocol/header bytes, malformed raw trees,
unsupported repository state, invalid public arguments, and exhausted
budgets raise :class:`SnapshotError` rather than being coerced.
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time
from bisect import bisect_left
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, BinaryIO, Callable

if TYPE_CHECKING:
    from receipt.protected_tree import _AttributeStore

from receipt._names import (
    NamePolicyError,
    validate_component_bytes,
    validate_repertoire,
)


GIT_MIN_VERSION = (2, 36, 0)
GIT_FSCK_NO_REFERENCES_MIN_VERSION = (2, 50, 0)

MAX_TREE_ENTRIES = 1_048_576
MAX_TREE_OBJECT_BYTES = 64 * 1024 * 1024
MAX_TREE_BYTES_TOTAL = 512 * 1024 * 1024
MAX_ENTRY_NAME_BYTES = 4_096
MAX_PATH_BYTES = 4_096
MAX_PATH_BYTES_TOTAL = 256 * 1024 * 1024
MAX_GIT_OUTPUT_BYTES = 1 * 1024 * 1024
MAX_GIT_SECONDS = 60
BATCH_KILL_REAP_SECONDS = 5
MAX_TREE_DEPTH = 256
MAX_ANCESTRY_COMMITS = 1_048_576
MAX_ATTRIBUTE_BYTES = 1 * 1024 * 1024
MAX_ATTRIBUTE_BYTES_TOTAL = 16 * 1024 * 1024
MAX_ATTRIBUTE_RULES_TOTAL = 65_536
MAX_ATTRIBUTE_STATES_PER_LINE = 256
MAX_ATTRIBUTE_MATCH_WORK = 67_108_864
MAX_CONTENT_BLOB_BYTES = 256 * 1024 * 1024
MAX_CONTENT_BYTES_TOTAL = 16 * 1024 * 1024 * 1024
MAX_MATERIALIZED_BYTES = 4 * 1024 * 1024 * 1024
MAX_MATERIALIZED_BLOB_BYTES = 64 * 1024 * 1024
MAX_FSCK_OBJECTS = 4_194_304
MAX_STORE_KIB = 16 * 1024 * 1024
MAX_FSCK_OUTPUT_BYTES = 1 * 1024 * 1024
MAX_FSCK_SECONDS = 600

_BATCH_CHUNK_BYTES = 1024 * 1024
_BATCH_HEADER_BYTES = 4096
_RAW_MODES = frozenset({b"100644", b"100755", b"120000", b"160000", b"40000"})
_CONTENT_MODES = frozenset({"100644", "100755"})
_OID_RE = re.compile(rb"[0-9a-f]+\Z")
_VERSION_RE = re.compile(r"\bgit version (\d+)\.(\d+)\.(\d+)")
_SURROGATE_PAIR_RE = re.compile("[\ud800-\udbff][\udc00-\udfff]")


def assert_no_merging_entries(
    names: Iterable[bytes | str], *, repertoire: str,
    materializing: bool = False, label: str = "tree directory",
) -> None:
    """Forward the existing local-name screen at its original caller barrier."""
    from receipt.protected_tree import screen_siblings

    screen_siblings(names, repertoire=repertoire, materializing=materializing, label=label)


def _ancestor_shape_error(finding, *, protected: bool = False) -> SnapshotError:
    """Keep the three D6 renderers at their legacy snapshot boundary."""
    if finding.kind == "missing":
        return SnapshotError(f"tree entry does not exist: {finding.target}")
    if protected:
        return SnapshotError(f"protected path ancestor is not a directory: {finding.prefix}")
    if finding.kind == "symlink":
        return SnapshotError(f"state path has a symlinked component: {finding.prefix}")
    return SnapshotError(f"tree path ancestor is not a directory: {finding.prefix}")


def _check_tree_ancestor(parts: tuple[bytes, ...], index: int, raw: _RawTreeEntry,
                         *, protected: bool = False) -> None:
    # The reader has already authenticated this reached component and charged
    # its walk. Do not look ahead, flatten a listing or fetch a protected blob.
    from receipt.protected_tree import ancestor_finding

    finding = ancestor_finding(
        _tree_path_decode(b"/".join(parts)),
        _tree_path_decode(b"/".join(parts[:index + 1])),
        raw.mode.decode("ascii").zfill(6), raw.object_type,
        position=(index,),
    )
    if finding is not None:
        raise _ancestor_shape_error(finding, protected=protected)


def _tree_path_decode(value: bytes) -> str:
    """Decode logical Git path bytes independently of the host filesystem."""

    return value.decode("utf-8", errors="surrogateescape")


def _tree_path_encode(value: str) -> bytes:
    """Encode logical Git path text independently of the host filesystem."""

    return value.encode("utf-8", errors="surrogateescape")


def _validate_expected_oid(value: object, *, label: str, object_format: str) -> str:
    """Return an exact auditor expectation without invoking hostile equality."""

    width = hashlib.new(object_format).digest_size * 2
    if (
        type(value) is not str
        or len(value) != width
        or re.fullmatch(r"[0-9a-f]+", value) is None
    ):
        raise SnapshotError(
            f"expected {label} must be a full lowercase hexadecimal object name"
        )
    return value


class SnapshotError(ValueError):
    """The repository cannot produce the authenticated immutable snapshot."""


@dataclass(frozen=True)
class GitEntry:
    """One tree entry, with Git's six-digit display mode and full path.

    The private binding is deliberately excluded from equality and repr. It
    lets payload APIs refuse entries forged, altered with ``replace()``, or
    obtained from a different snapshot without turning every streamed blob
    into a second path walk. Four-argument construction remains
    source-compatible, but an unbound entry cannot authorize an object read.
    """

    mode: str
    object_type: str
    object_id: str
    path: str
    _snapshot_token: object | None = field(
        default=None, repr=False, compare=False
    )


@dataclass(frozen=True)
class _EntryBinding:
    snapshot_token: object
    mode: str
    object_type: str
    object_id: str
    path: str


@dataclass(frozen=True)
class ObjectStoreReport:
    """The bounded result of an explicitly requested primary-store fsck."""

    objects: int
    store_kib: int
    seconds: float


@dataclass
class SnapshotWork:
    """Observable work counters used to prove fixtures remain below ceilings."""

    tree_entries: int = 0
    max_tree_entries_in_walk: int = 0
    tree_bytes: int = 0
    max_tree_object_bytes: int = 0
    path_bytes: int = 0
    max_path_bytes: int = 0
    ancestry_commits: int = 0
    ancestry_edges: int = 0
    attribute_bytes: int = 0
    attribute_rules: int = 0
    attribute_match_work: int = 0
    content_bytes: int = 0
    max_content_blob_bytes: int = 0
    materialized_bytes: int = 0
    max_materialized_blob_bytes: int = 0


@dataclass
class _WorkPool:
    """Union-find node grouping verification-wide counters across snapshots."""

    works: list[SnapshotWork]
    parent: "_WorkPool | None" = None

    attributes: "_AttributeStore | None" = None

    def root(self) -> "_WorkPool":
        if self.parent is None:
            return self
        self.parent = self.parent.root()
        return self.parent


@dataclass(frozen=True)
class _RawTreeEntry:
    mode: bytes
    name: bytes
    oid: str

    @property
    def display_mode(self) -> str:
        return "040000" if self.mode == b"40000" else self.mode.decode("ascii")

    @property
    def object_type(self) -> str:
        if self.mode == b"40000":
            return "tree"
        if self.mode == b"160000":
            return "commit"
        return "blob"


@dataclass(frozen=True)
class _CommitObject:
    oid: str
    tree: str
    parents: tuple[str, ...]


@dataclass
class _SnapshotState:
    root: pathlib.Path
    common_dir: pathlib.Path
    revision: str
    version: tuple[int, int, int]
    config_records: tuple[tuple[str, str, str], ...]
    global_config_bytes: bytes
    verify_objects_ready: bool
    selected_commit: _CommitObject
    root_tree: tuple[_RawTreeEntry, ...]
    work: SnapshotWork
    work_pool: _WorkPool
    tree_cache: dict[str, tuple[_RawTreeEntry, ...]]
    commit_cache: dict[str, _CommitObject]
    entry_token: object = field(default_factory=object)
    ancestry_bases: set[str] = field(default_factory=set)
    object_store_attempted: bool = False
    attribute_cache: dict[str, tuple["_AttributeRule", ...]] = field(
        default_factory=dict
    )
    entered: bool = False
    closed: bool = False
    abandoned: bool = False
    active_digest_token: object | None = None
    batch: "_BatchReader | None" = None
    tempdir: "tempfile.TemporaryDirectory[str] | None" = None
    global_config: pathlib.Path | None = None


# These are the 73 variables documented by git(1) 2.53.0. Enforcement is the
# prefix rule in _git_environment; this tuple makes the boundary reviewable.
GIT_ENVIRONMENT_DROPPED_DOCUMENTED = (
    "GIT_ADVICE",
    "GIT_ALLOW_PROTOCOL",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_ASKPASS",
    "GIT_ATTR_SOURCE",
    "GIT_AUTHOR_DATE",
    "GIT_AUTHOR_EMAIL",
    "GIT_AUTHOR_NAME",
    "GIT_CEILING_DIRECTORIES",
    "GIT_COMMITTER_DATE",
    "GIT_COMMITTER_EMAIL",
    "GIT_COMMITTER_NAME",
    "GIT_COMMIT_GRAPH_PARANOIA",
    "GIT_COMMON_DIR",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_CONFIG_SYSTEM",
    "GIT_DEFAULT_HASH",
    "GIT_DEFAULT_REF_FORMAT",
    "GIT_DIFF_OPTS",
    "GIT_DIFF_PATH_COUNTER",
    "GIT_DIFF_PATH_TOTAL",
    "GIT_DIR",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_EDITOR",
    "GIT_EXEC_PATH",
    "GIT_EXTERNAL_DIFF",
    "GIT_EXTERNAL_DIFF_TRUST_EXIT_CODE",
    "GIT_FLUSH",
    "GIT_GLOB_PATHSPECS",
    "GIT_ICASE_PATHSPECS",
    "GIT_INDEX_FILE",
    "GIT_INDEX_VERSION",
    "GIT_LITERAL_PATHSPECS",
    "GIT_MERGE_VERBOSITY",
    "GIT_NAMESPACE",
    "GIT_NOGLOB_PATHSPECS",
    "GIT_NO_LAZY_FETCH",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_OBJECT_DIRECTORY",
    "GIT_OPTIONAL_LOCKS",
    "GIT_PAGER",
    "GIT_PRINT_SHA1_ELLIPSIS",
    "GIT_PROGRESS_DELAY",
    "GIT_PROTOCOL",
    "GIT_PROTOCOL_FROM_USER",
    "GIT_REDIRECT_STDERR",
    "GIT_REDIRECT_STDIN",
    "GIT_REDIRECT_STDOUT",
    "GIT_REFLOG_ACTION",
    "GIT_REF_PARANOIA",
    "GIT_SEQUENCE_EDITOR",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_SSH_VARIANT",
    "GIT_SSL_NO_VERIFY",
    "GIT_TERMINAL_PROMPT",
    "GIT_TRACE",
    "GIT_TRACE2",
    "GIT_TRACE2_EVENT",
    "GIT_TRACE2_PERF",
    "GIT_TRACE_CURL",
    "GIT_TRACE_CURL_NO_DATA",
    "GIT_TRACE_FSMONITOR",
    "GIT_TRACE_PACKET",
    "GIT_TRACE_PACKFILE",
    "GIT_TRACE_PACK_ACCESS",
    "GIT_TRACE_PERFORMANCE",
    "GIT_TRACE_REDACT",
    "GIT_TRACE_REFS",
    "GIT_TRACE_SETUP",
    "GIT_TRACE_SHALLOW",
    "GIT_WORK_TREE",
)

GIT_ENVIRONMENT_DROPPED_UNDOCUMENTED = (
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_KEY_<n>",
    "GIT_CONFIG_VALUE_<n>",
)

GIT_ENVIRONMENT_DROPPED = (
    *GIT_ENVIRONMENT_DROPPED_DOCUMENTED,
    *GIT_ENVIRONMENT_DROPPED_UNDOCUMENTED,
)

# Templates, not shell strings: every production Git child must match one.
GIT_COMMANDS = (
    ("setup", "config", "-f", "<global>", "safe.directory", "<root>"),
    ("discovery", "version"),
    ("discovery", "version", "--build-options"),
    (
        "discovery",
        "rev-parse",
        "--show-toplevel",
        "--absolute-git-dir",
        "--git-common-dir",
        "--show-object-format",
    ),
    ("discovery", "config", "--list", "--show-scope", "--no-includes", "-z"),
    ("object", "rev-parse", "--verify", "--end-of-options", "<rev>^{commit}"),
    ("object", "cat-file", "--batch-command"),
    ("object", "count-objects", "-v"),
    (
        "object",
        "-c",
        "core.commitGraph=false",
        "fsck",
        "--full",
        "--no-dangling",
        "--no-reflogs",
        "--no-references",
        "--no-progress",
        "<candidate>",
        "[<base>]",
    ),
)


def _git_environment(global_config: pathlib.Path | str) -> dict[str, str]:
    """Return the exact environment for every Git child.

    Every inherited name beginning ``GIT_`` is removed, including numbered
    config channels and names introduced by a later Git. Exactly three Git
    variables are installed. ``HOME`` and all non-Git ambient variables
    survive; global and system configuration are redirected instead.
    """

    environment = {
        name: value for name, value in os.environ.items() if not name.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.fspath(global_config),
        }
    )
    return environment


def _kill_reap_and_close(process: subprocess.Popen[bytes]) -> None:
    """Best-effort cleanup for a child which could not finish setup."""

    if process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=MAX_GIT_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        pass
    for pipe in (process.stdin, process.stdout, process.stderr):
        if pipe is not None:
            try:
                pipe.close()
            except OSError:
                pass


def _bounded_process(
    argv: Sequence[str],
    *,
    cwd: pathlib.Path | None,
    environment: Mapping[str, str],
    input_bytes: bytes | None,
    output_limit: int,
    seconds: float,
) -> subprocess.CompletedProcess[bytes]:
    """Run one child while retaining at most ``output_limit`` output bytes."""

    try:
        process = subprocess.Popen(
            list(argv),
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise SnapshotError("git is required to read an immutable tree snapshot") from exc

    assert process.stdout is not None
    assert process.stderr is not None
    output = [bytearray(), bytearray()]
    drain_failures: list[BaseException] = []
    total = 0
    exceeded = False
    lock = threading.Lock()
    started_threads: list[threading.Thread] = []
    primary_error: BaseException | None = None

    def drain(pipe: BinaryIO, target: bytearray) -> None:
        nonlocal total, exceeded
        try:
            while True:
                chunk = pipe.read(65_536)
                if not chunk:
                    return
                with lock:
                    remaining = output_limit + 1 - total
                    if remaining > 0:
                        target.extend(chunk[:remaining])
                        total += min(len(chunk), remaining)
                    if len(chunk) > remaining or total > output_limit:
                        exceeded = True
                        try:
                            process.kill()
                        except ProcessLookupError:
                            pass
        except BaseException as caught:
            with lock:
                drain_failures.append(caught)
            try:
                process.kill()
            except OSError:
                pass

    try:
        threads = (
            threading.Thread(
                target=drain, args=(process.stdout, output[0]), daemon=True
            ),
            threading.Thread(
                target=drain, args=(process.stderr, output[1]), daemon=True
            ),
        )
        for thread in threads:
            thread.start()
            started_threads.append(thread)
        if input_bytes is not None:
            assert process.stdin is not None
            try:
                process.stdin.write(input_bytes)
            except (BrokenPipeError, OSError):
                pass
            finally:
                try:
                    process.stdin.close()
                except OSError:
                    pass
        try:
            returncode = process.wait(timeout=seconds)
        except subprocess.TimeoutExpired as exc:
            raise SnapshotError(
                f"git command exceeded its {seconds:g} second budget"
            ) from exc
        for thread in threads:
            thread.join(MAX_GIT_SECONDS)
            if thread.is_alive():
                raise SnapshotError("git output drain did not finish")
        if drain_failures:
            raise SnapshotError("git output could not be read") from drain_failures[0]
        if exceeded:
            raise SnapshotError(
                f"git output exceeds the budget of {output_limit} bytes"
            )
        return subprocess.CompletedProcess(
            list(argv), returncode, bytes(output[0]), bytes(output[1])
        )
    except BaseException as caught:
        primary_error = caught
        raise
    finally:
        cleanup_failures: list[BaseException] = []
        reaped = getattr(process, "returncode", None) is not None
        if not reaped:
            try:
                process.kill()
            except OSError:
                pass
            except BaseException as caught:
                cleanup_failures.append(caught)
            try:
                process.wait(timeout=MAX_GIT_SECONDS)
            except BaseException as caught:
                cleanup_failures.append(caught)
            else:
                reaped = True
        deadline = time.monotonic() + MAX_GIT_SECONDS
        for thread in started_threads:
            try:
                thread.join(max(0.0, deadline - time.monotonic()))
            except BaseException as caught:
                cleanup_failures.append(caught)
        for pipe in (process.stdin, process.stdout, process.stderr):
            if pipe is None:
                continue
            try:
                pipe.close()
            except OSError:
                pass
            except BaseException as caught:
                cleanup_failures.append(caught)
        if any(thread.is_alive() for thread in started_threads):
            cleanup_failures.append(SnapshotError("git output drain did not finish"))
        if not reaped:
            cleanup_failures.append(SnapshotError("git child could not be reaped"))
        if cleanup_failures:
            cleanup_error = SnapshotError("git child cleanup failed")
            for failure in cleanup_failures[1:]:
                cleanup_error.add_note(f"Additional cleanup failure: {failure}")
            if primary_error is not None:
                primary_error.add_note(f"Git child cleanup also failed: {cleanup_error}")
            else:
                raise cleanup_error from cleanup_failures[0]


def _git_run(
    arguments: Sequence[str],
    *,
    cwd: pathlib.Path | None,
    environment: Mapping[str, str],
    output_limit: int = MAX_GIT_OUTPUT_BYTES,
    seconds: float = MAX_GIT_SECONDS,
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run one allow-listed Git command without a shell and with hard bounds."""

    return _bounded_process(
        ("git", *arguments),
        cwd=cwd,
        environment=environment,
        input_bytes=input_bytes,
        output_limit=output_limit,
        seconds=seconds,
    )


def _first_error(completed: subprocess.CompletedProcess[bytes]) -> str:
    output = completed.stderr or completed.stdout
    text = output.decode("utf-8", errors="replace").strip()
    return text.splitlines()[0] if text else f"git exited {completed.returncode}"


def _object_arguments(git_dir: pathlib.Path, arguments: Sequence[str]) -> list[str]:
    return [f"--git-dir={git_dir}", "--no-replace-objects", *arguments]


def _parse_version(output: bytes) -> tuple[int, int, int]:
    match = _VERSION_RE.search(output.decode("ascii", errors="replace"))
    if match is None:
        raise SnapshotError("git version output is not recognized")
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch)


def _parse_config(output: bytes) -> tuple[tuple[str, str, str], ...]:
    """Parse scoped ``--list -z`` records, including implicit booleans."""

    fields = output.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    if len(fields) % 2:
        raise SnapshotError("repository configuration listing is malformed")
    records: list[tuple[str, str, str]] = []
    for index in range(0, len(fields), 2):
        try:
            scope = fields[index].decode("utf-8", errors="strict")
            key_value = fields[index + 1].decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise SnapshotError("repository configuration is not UTF-8") from exc
        key, separator, value = key_value.partition("\n")
        if not scope or not key:
            raise SnapshotError("repository configuration listing is malformed")
        if not separator:
            value = "true"
        records.append((scope, key, value))
    return tuple(records)


def _config_bool(key: str, value: str) -> bool:
    """Classify a boolean configuration value as git 2.53.0 does.

    ``true``, ``yes``, ``on`` and ``1`` are true, and so is the valueless
    form, which ``_parse_config`` already spells ``true``; ``false``, ``no``,
    ``off``, ``0`` and an explicitly empty value (``ignorecase =``) are false,
    as ``git config --type=bool`` reports them (peer review, round 4). Git
    reads any other integer as true when it is non-zero and dies on other
    text; this reader refuses both, deliberately narrower than git, because
    its configuration audit accepts only that closed boolean set.
    """

    lowered = value.strip().lower()
    if lowered in {"true", "yes", "on", "1"}:
        return True
    if lowered in {"", "false", "no", "off", "0"}:
        return False
    raise SnapshotError(f"repository configuration key {key!r} has a non-boolean value {value!r}")


def _config_key_denied(key: str) -> bool:
    lowered = key.lower()
    return (
        lowered.startswith("include.")
        or lowered.startswith("includeif.")
        or lowered
        in {
            "core.fsmonitor",
            "core.hookspath",
            "core.alternaterefscommand",
            "core.gitproxy",
            "core.sshcommand",
            "core.askpass",
            "extensions.partialclone",
        }
        or (lowered.startswith("remote.") and lowered.endswith(".promisor"))
        or (
            lowered.startswith("remote.")
            and lowered.endswith(".partialclonefilter")
        )
        or lowered.startswith("fsck.")
        or lowered.startswith("receive.fsck.")
        or lowered.startswith("transfer.fsck")
    )


def _audit_config(
    records: tuple[tuple[str, str, str], ...], root: pathlib.Path
) -> None:
    global_records = [
        (key.lower(), value)
        for scope, key, value in records
        if scope == "global"
    ]
    if global_records != [("safe.directory", os.fspath(root))]:
        raise SnapshotError(
            "the private global Git configuration does not contain exactly "
            "the selected safe.directory"
        )
    if any(scope == "system" for scope, _, _ in records):
        raise SnapshotError("system Git configuration was not disabled")
    for scope, key, _ in records:
        if scope in {"local", "worktree"} and _config_key_denied(key):
            raise SnapshotError(
                f"repository configuration key {key!r} is not allowed for "
                "immutable tree reads"
            )
    for scope, key, value in records:
        if scope in {"local", "worktree"} and key.lower() == "core.ignorecase":
            _config_bool(key, value)


def _create_global_config(root: pathlib.Path) -> bytes:
    """Serialize safe.directory from a private cwd with no ambient repository."""

    with tempfile.TemporaryDirectory(prefix="receipt-snapshot-select-") as directory:
        private_directory = pathlib.Path(directory)
        path = private_directory / "global.gitconfig"
        environment = _git_environment(path)
        completed = _git_run(
            ["config", "-f", os.fspath(path), "safe.directory", os.fspath(root)],
            cwd=private_directory,
            environment=environment,
        )
        if completed.returncode != 0:
            raise SnapshotError(
                f"cannot create private Git configuration: {_first_error(completed)}"
            )
        try:
            return path.read_bytes()
        except OSError as exc:
            raise SnapshotError("cannot read the private Git configuration") from exc


def _raw_tree_sort_key(entry: _RawTreeEntry) -> bytes:
    return entry.name + (b"/" if entry.mode == b"40000" else b"")


def _parse_raw_tree(
    oid: str, payload: bytes, *, object_format: str
) -> tuple[_RawTreeEntry, ...]:
    oid_bytes = hashlib.new(object_format).digest_size
    position = 0
    entries: list[_RawTreeEntry] = []
    names: set[bytes] = set()
    previous_key: bytes | None = None
    # M1 record, raw-tree row 797-844: structural admission precedes policy facts.
    while position < len(payload):
        if len(entries) >= MAX_TREE_ENTRIES:
            raise SnapshotError(
                f"tree walk exceeds the budget of {MAX_TREE_ENTRIES} entries"
            )
        space = payload.find(b" ", position)
        if space < 0:
            raise SnapshotError(f"tree {oid} has a malformed entry")
        mode = payload[position:space]
        if mode not in _RAW_MODES:
            shown = mode.decode("ascii", errors="backslashreplace")
            raise SnapshotError(f"tree {oid} has unsupported raw mode {shown!r}")
        nul = payload.find(b"\0", space + 1)
        if nul < 0:
            raise SnapshotError(f"tree {oid} has a malformed entry")
        name = payload[space + 1 : nul]
        if len(name) > MAX_ENTRY_NAME_BYTES:
            raise SnapshotError(
                f"tree entry name exceeds the budget of {MAX_ENTRY_NAME_BYTES} bytes"
            )
        try:
            validate_component_bytes(name)
        except NamePolicyError as exc:
            raise SnapshotError(f"tree {oid} has an invalid entry name: {exc}") from exc
        binary_start = nul + 1
        binary_end = binary_start + oid_bytes
        if binary_end > len(payload):
            raise SnapshotError(f"tree {oid} has a truncated object name")
        object_id = payload[binary_start:binary_end].hex()
        entry = _RawTreeEntry(mode=mode, name=name, oid=object_id)
        if name in names:
            raise SnapshotError(f"tree {oid} contains duplicate entry name {name!r}")
        key = _raw_tree_sort_key(entry)
        if previous_key is not None and key <= previous_key:
            raise SnapshotError(f"tree {oid} entries are not in canonical Git order")
        entries.append(entry)
        names.add(name)
        previous_key = key
        position = binary_end
    return tuple(entries)


def _canonical_commit(
    oid: str,
    payload: bytes,
    *,
    object_format: str,
    parent_limit: int | None = None,
) -> _CommitObject:
    """Parse exactly the canonical commit-header shape fixed by the plan."""

    separator = payload.find(b"\n\n")
    if separator < 0:
        raise SnapshotError(f"commit {oid} is not a canonical commit object")

    if parent_limit is None:
        parent_limit = MAX_ANCESTRY_COMMITS
    hex_length = hashlib.new(object_format).digest_size * 2

    def object_name(value: bytes) -> str:
        if len(value) != hex_length or _OID_RE.fullmatch(value) is None:
            raise SnapshotError(f"commit {oid} is not a canonical commit object")
        return value.decode("ascii")

    tree: str | None = None
    parents: list[str] = []
    parent_overflow = False
    phase = "tree"

    def accept_header(name: bytes, value: bytes) -> None:
        nonlocal parent_overflow, phase, tree
        if phase == "tree":
            if name != b"tree":
                raise SnapshotError(
                    f"commit {oid} is not a canonical commit object"
                )
            tree = object_name(value)
            phase = "parents"
            return
        if phase == "parents":
            if name == b"parent":
                parent = object_name(value)
                if len(parents) >= parent_limit:
                    parent_overflow = True
                else:
                    parents.append(parent)
                return
            if name != b"author":
                raise SnapshotError(
                    f"commit {oid} is not a canonical commit object"
                )
            phase = "committer"
            return
        if phase == "committer":
            if name != b"committer":
                raise SnapshotError(
                    f"commit {oid} is not a canonical commit object"
                )
            phase = "later"
            return
        if name in {b"tree", b"parent", b"author", b"committer"}:
            raise SnapshotError(f"commit {oid} is not a canonical commit object")

    # Commit framing names LF exactly. Scan it directly so a hostile commit
    # cannot allocate a second list containing every physical header line.
    position = 0
    current_name: bytes | None = None
    current_value = b""
    while position <= separator:
        line_end = payload.find(b"\n", position, separator)
        if line_end < 0:
            line_end = separator
        line = payload[position:line_end]
        position = line_end + 1
        if line.startswith(b" "):
            if current_name is None:
                raise SnapshotError(
                    f"commit {oid} is not a canonical commit object"
                )
            if current_name in {b"tree", b"parent"}:
                current_value += b"\n" + line[1:]
            continue
        if current_name is not None:
            accept_header(current_name, current_value)
        name, space, value = line.partition(b" ")
        if (
            not space
            or not name
            or any(byte <= 0x20 or byte >= 0x7F for byte in name)
        ):
            raise SnapshotError(f"commit {oid} is not a canonical commit object")
        current_name = name
        current_value = value if name in {b"tree", b"parent"} else b""
    if current_name is not None:
        accept_header(current_name, current_value)
    if tree is None or phase != "later":
        raise SnapshotError(f"commit {oid} is not a canonical commit object")
    if parent_overflow:
        raise SnapshotError(
            f"ancestry walk exceeds the budget of "
            f"{MAX_ANCESTRY_COMMITS} commits"
        )
    return _CommitObject(oid=oid, tree=tree, parents=tuple(parents))


def _unsupported_attribute(path: str, line: int, construct: str) -> SnapshotError:
    from receipt import protected_tree

    return protected_tree._unsupported_attribute(path, line, construct)


def _attribute_pattern(
    token: bytes, *, path: str, line: int
) -> tuple[bytes, tuple[bytes, ...], bool]:
    from receipt import protected_tree

    return protected_tree._attribute_pattern(token, path=path, line=line)


def _parse_attribute_file(
    path: str, payload: bytes, *, rule_limit: int
) -> tuple[_AttributeRule, ...]:
    from receipt import protected_tree

    return protected_tree._parse_attribute_file(path, payload, rule_limit=rule_limit)


def _segment_matches(
    pattern: bytes, value: bytes, step: Callable[[], None]
) -> bool:
    from receipt import protected_tree

    return protected_tree._segment_matches(pattern, value, step)


def _attribute_matches(
    rule: _AttributeRule, relative: tuple[bytes, ...], step: Callable[[], None]
) -> bool:
    from receipt import protected_tree

    return protected_tree._attribute_matches(rule, relative, step)


class _BatchReader:
    """One framed ``cat-file --batch-command`` conversation."""

    def __init__(
        self,
        git_dir: pathlib.Path,
        *,
        environment: Mapping[str, str],
        object_format: str,
    ) -> None:
        self._object_format = object_format
        self._abandoned = False
        self._closed = False
        self._headers: dict[str, tuple[str, int]] = {}
        self._stderr_bytes = bytearray()
        self._stderr_truncated = False
        try:
            self._process = subprocess.Popen(
                [
                    "git",
                    *_object_arguments(git_dir, ["cat-file", "--batch-command"]),
                ],
                cwd=None,
                env=dict(environment),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
            )
        except FileNotFoundError as exc:
            raise SnapshotError("git is required to read an immutable tree snapshot") from exc
        try:
            if (
                self._process.stdin is None
                or self._process.stdout is None
                or self._process.stderr is None
            ):
                raise SnapshotError("cannot open the Git batch object's pipes")
            self._stdin = self._process.stdin
            self._stdout = self._process.stdout
            self._stderr_thread = threading.Thread(
                target=self._drain_stderr,
                name="receipt-git-batch-stderr",
                daemon=True,
            )
            self._stderr_thread.start()
        except BaseException:
            _kill_reap_and_close(self._process)
            raise

    def _drain_stderr(self) -> None:
        """Drain stderr continuously while retaining only the bounded prefix."""

        pipe = self._process.stderr
        if pipe is None:
            return
        try:
            while chunk := pipe.read(_BATCH_CHUNK_BYTES):
                remaining = MAX_GIT_OUTPUT_BYTES - len(self._stderr_bytes)
                if remaining > 0:
                    self._stderr_bytes.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    self._stderr_truncated = True
        except OSError:
            return

    @property
    def abandoned(self) -> bool:
        return self._abandoned

    @property
    def process(self) -> subprocess.Popen[bytes]:
        return self._process

    def _usable(self) -> None:
        if self._abandoned:
            raise SnapshotError("snapshot stream was abandoned")
        if self._closed:
            raise SnapshotError("snapshot is closed")

    def abandon(self) -> None:
        self._abandoned = True

    def _request(self, command: str, oid: str) -> None:
        self._usable()
        try:
            self._stdin.write(f"{command} {oid}\n".encode("ascii"))
            self._stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            self._abandoned = True
            raise SnapshotError("Git batch child stopped accepting requests") from exc
        except BaseException:
            # The write may have stopped after an arbitrary prefix. No later
            # request may guess whether Git received a complete command.
            self._abandoned = True
            try:
                self._process.kill()
            except OSError:
                pass
            raise

    def _read_with_deadline(
        self, operation: Callable[[], bytes], *, deadline: float
    ) -> bytes:
        """Run one pipe read without allowing the batch child to hang us."""

        result: list[bytes] = []
        failure: list[BaseException] = []

        def read() -> None:
            try:
                result.append(operation())
            except BaseException as exc:
                failure.append(exc)

        try:
            reader = threading.Thread(
                target=read,
                name="receipt-git-batch-stdout",
                daemon=True,
            )
            reader.start()
        except BaseException:
            self._abandoned = True
            try:
                self._process.kill()
            except OSError:
                pass
            raise
        try:
            reader.join(max(0.0, deadline - time.monotonic()))
            if reader.is_alive():
                raise SnapshotError(
                    f"Git batch child exceeded the budget of "
                    f"{MAX_GIT_SECONDS} seconds"
                )
            if failure:
                raise SnapshotError("Git batch child could not be read") from failure[0]
            if not result:
                raise SnapshotError("Git batch child could not be read")
            return result[0]
        except BaseException:
            # An interruption while the helper thread owns stdout leaves the
            # frame position unknowable even if that thread later completes.
            self._abandoned = True
            try:
                self._process.kill()
            except OSError:
                pass
            try:
                reader.join(max(0.0, deadline - time.monotonic()))
            except BaseException:
                pass
            raise

    def _line(self, *, deadline: float) -> bytes:
        line = self._read_with_deadline(
            lambda: self._stdout.readline(_BATCH_HEADER_BYTES + 1),
            deadline=deadline,
        )
        if len(line) > _BATCH_HEADER_BYTES or not line.endswith(b"\n"):
            self._abandoned = True
            raise SnapshotError("batch stream out of frame")
        return line[:-1]

    def _parse_header(self, requested: str, line: bytes) -> tuple[str, int]:
        if line == f"{requested} missing".encode("ascii"):
            raise SnapshotError(f"object {requested} is unavailable")
        parts = line.split(b" ")
        if len(parts) != 3:
            self._abandoned = True
            raise SnapshotError("batch stream out of frame")
        try:
            returned = parts[0].decode("ascii")
            object_type = parts[1].decode("ascii")
            size_text = parts[2].decode("ascii")
        except UnicodeDecodeError as exc:
            self._abandoned = True
            raise SnapshotError("batch stream out of frame") from exc
        if returned != requested or not size_text.isdecimal():
            self._abandoned = True
            raise SnapshotError("batch stream out of frame")
        size = int(size_text)
        return object_type, size

    def info(self, oid: str, *, role: str | None = None) -> tuple[str, int]:
        self._usable()
        header = self._headers.get(oid)
        if header is None:
            self._request("info", oid)
            header = self._parse_header(
                oid,
                self._line(deadline=time.monotonic() + MAX_GIT_SECONDS),
            )
            self._headers[oid] = header
        if role is not None and header[0] != role:
            raise SnapshotError(
                f"object {oid} is a {header[0]}, not the {role} its reference requires"
            )
        return header

    def consume(
        self,
        oid: str,
        *,
        role: str,
        limit: int,
        consumer: Callable[[bytes], None] | None = None,
        hold: bool = False,
    ) -> bytes | None:
        """Consume one complete contents frame and authenticate the payload."""

        object_type, size = self.info(oid, role=role)
        if size > limit:
            raise SnapshotError(
                f"object {oid} exceeds the payload budget of {limit} bytes"
            )
        self._request("contents", oid)
        deadline = time.monotonic() + MAX_GIT_SECONDS
        response_type, response_size = self._parse_header(
            oid, self._line(deadline=deadline)
        )
        if (response_type, response_size) != (object_type, size):
            self._abandoned = True
            raise SnapshotError("batch stream out of frame")

        object_hash = hashlib.new(self._object_format)
        object_hash.update(f"{object_type} {size}\0".encode("ascii"))
        retained = bytearray() if hold else None
        remaining = size
        try:
            while remaining:
                chunk = self._read_with_deadline(
                    lambda: self._stdout.read(
                        min(_BATCH_CHUNK_BYTES, remaining)
                    ),
                    deadline=deadline,
                )
                if not chunk:
                    self._abandoned = True
                    raise SnapshotError("batch stream out of frame")
                remaining -= len(chunk)
                object_hash.update(chunk)
                if retained is not None:
                    retained.extend(chunk)
                if consumer is not None:
                    consumer(chunk)
        except BaseException:
            # Even when the callback failed on the final payload chunk, the
            # framing LF remains unread, so every callback failure abandons
            # the stream rather than guessing at its position.
            self._abandoned = True
            raise
        if self._read_with_deadline(
            lambda: self._stdout.read(1), deadline=deadline
        ) != b"\n":
            self._abandoned = True
            raise SnapshotError("batch stream out of frame")
        if object_hash.hexdigest() != oid:
            self._abandoned = True
            raise SnapshotError(f"object {oid} does not hash to its name")
        return bytes(retained) if retained is not None else None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        was_abandoned = self._abandoned
        deadline = time.monotonic() + MAX_GIT_SECONDS

        failures: list[BaseException] = []

        def kill() -> None:
            try:
                self._process.kill()
            except OSError:
                pass
            except BaseException as caught:
                failures.append(caught)

        def wait(wait_deadline: float) -> bool:
            try:
                self._process.wait(
                    timeout=max(0.0, wait_deadline - time.monotonic())
                )
            except subprocess.TimeoutExpired:
                return False
            except BaseException as caught:
                failures.append(caught)
                return False
            return True

        reaped = False
        wait_deadline = deadline
        try:
            if was_abandoned and self._process.poll() is None:
                kill()
                wait_deadline = time.monotonic() + BATCH_KILL_REAP_SECONDS
            try:
                self._stdin.close()
            except OSError:
                pass
            reaped = wait(wait_deadline)
            if not reaped:
                kill()
                wait_deadline = time.monotonic() + BATCH_KILL_REAP_SECONDS
                reaped = wait(wait_deadline)
        finally:
            # Cleanup is deliberately independent: an injected failure in one
            # operation must not skip the remaining pipe closes or reap attempt.
            if not reaped:
                kill()
                wait_deadline = time.monotonic() + BATCH_KILL_REAP_SECONDS
                reaped = wait(wait_deadline)
            try:
                self._stderr_thread.join(
                    max(0.0, wait_deadline - time.monotonic())
                )
            except BaseException as caught:
                failures.append(caught)
            for pipe in (self._stdin, self._stdout, self._process.stderr):
                if pipe is None:
                    continue
                try:
                    pipe.close()
                except OSError:
                    pass
                except BaseException as caught:
                    failures.append(caught)
            if self._stderr_thread.is_alive():
                failures.append(
                    SnapshotError("Git batch stderr drain did not finish")
                )
        if not reaped:
            failures.append(SnapshotError("Git batch child could not be reaped"))
        if failures:
            error = SnapshotError("Git batch child cleanup failed")
            for failure in failures[1:]:
                error.add_note(f"Additional cleanup failure: {failure}")
            raise error from failures[0]
        if not was_abandoned and self._process.returncode != 0:
            detail = bytes(self._stderr_bytes).decode(
                "utf-8", errors="replace"
            ).splitlines()
            first = detail[0] if detail else "no diagnostic"
            if self._stderr_truncated:
                first += " (diagnostic output truncated)"
            raise SnapshotError(f"Git batch child failed: {first}")

    def __enter__(self) -> "_BatchReader":
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        exc: BaseException | None,
        _traceback: object,
    ) -> None:
        try:
            self.close()
        except BaseException as closing_error:
            if exc is not None:
                exc.add_note(f"Git batch close also failed: {closing_error}")
            else:
                raise


@dataclass(frozen=True)
class _ListingRecord:
    raw: _RawTreeEntry
    child: "_TreeNode | None" = None


@dataclass(frozen=True)
class _TreeNode:
    records: tuple[_ListingRecord, ...]
    tree_oid: str | None


@dataclass(frozen=True)
class _AttributeRule:
    pattern: bytes
    segments: tuple[bytes, ...]
    match_segments: tuple[bytes, ...]
    has_slash: bool
    trailing_descendants: bool
    states: tuple[tuple[str, str], ...]
    source_line: int = field(default=0, kw_only=True, compare=False)


@dataclass(frozen=True)
class TreeListing:
    """A hierarchical tree listing whose nodes store each local name once."""

    _snapshot: "TreeSnapshot" = field(repr=False, compare=False)
    _prefix: tuple[bytes, ...] = field(repr=False)
    _node: _TreeNode = field(repr=False)

    @property
    def tree_oid(self) -> str | None:
        return self._node.tree_oid

    # M1 record, snapshot entry/listing APIs: tree/leaf iteration is reader metadata.
    def _walk_from(
        self,
        node: _TreeNode,
        prefix: tuple[bytes, ...],
        *,
        include_trees: bool,
    ) -> Iterator[tuple[tuple[bytes, ...], _RawTreeEntry]]:
        for record in node.records:
            parts = (*prefix, record.raw.name)
            if include_trees or record.raw.mode != b"40000":
                yield parts, record.raw
            if record.child is not None:
                yield from self._walk_from(
                    record.child, parts, include_trees=include_trees
                )

    def _walk(
        self, *, include_trees: bool = False
    ) -> Iterator[tuple[tuple[bytes, ...], _RawTreeEntry]]:
        yield from self._walk_from(
            self._node, self._prefix, include_trees=include_trees
        )

    def iter_entries(
        self,
        *,
        include_trees: bool = False,
        _digest_token: object | None = None,
    ) -> Iterator[GitEntry]:
        """Build and charge full paths only as the caller asks for them."""

        self._snapshot._batch(digest_token=_digest_token)
        for parts, raw in self._walk(include_trees=include_trees):
            yield self._snapshot._public_entry(parts, raw)

    def __iter__(self) -> Iterator[GitEntry]:
        return self.iter_entries()

    def __len__(self) -> int:
        self._snapshot._batch()
        return sum(1 for _parts, raw in self._walk() if raw.mode != b"40000")

    @property
    def children(self) -> Mapping[str, GitEntry | "TreeListing"]:
        """Immediate children keyed by a lossless surrogateescaped spelling."""

        self._snapshot._batch()
        children: dict[str, GitEntry | TreeListing] = {}
        for record in self._node.records:
            name = _tree_path_decode(record.raw.name)
            if record.child is not None:
                children[name] = TreeListing(
                    self._snapshot,
                    (*self._prefix, record.raw.name),
                    record.child,
                )
            else:
                children[name] = self._snapshot._public_entry(
                    (*self._prefix, record.raw.name), record.raw
                )
        return MappingProxyType(children)

    def as_dict(self, *, include_trees: bool = False) -> dict[str, GitEntry]:
        """Return an explicitly requested flat view, charging every full path."""

        return {
            entry.path: entry
            for entry in self.iter_entries(include_trees=include_trees)
        }


class _DigestIterator(Iterator[tuple[GitEntry, str]]):
    """A conservative iterator which abandons its snapshot unless exhausted."""

    def __init__(
        self,
        snapshot: "TreeSnapshot",
        entries: Iterable[GitEntry],
        *,
        per_blob: int,
        total: int,
    ) -> None:
        self._snapshot = snapshot
        self._token = object()
        if snapshot._state.active_digest_token is not None:
            snapshot._abandon()
            raise SnapshotError("snapshot stream was abandoned")
        try:
            if type(entries) is TreeListing:
                self._entries = entries.iter_entries(
                    _digest_token=self._token
                )
            else:
                self._entries = iter(entries)
        except TypeError as exc:
            raise SnapshotError(
                "digests entries must be an iterable of GitEntry objects"
            ) from exc
        snapshot._state.active_digest_token = self._token
        self._per_blob = per_blob
        self._total = total
        self._charged = 0
        self._count = 0
        self._done = False
        self._closed = False

    def __iter__(self) -> "_DigestIterator":
        return self

    def __next__(self) -> tuple[GitEntry, str]:
        if self._done or self._closed:
            raise StopIteration
        try:
            self._snapshot._batch(digest_token=self._token)
        except BaseException:
            self.close()
            raise
        try:
            entry = next(self._entries)
        except StopIteration:
            self._done = True
            if self._snapshot._state.active_digest_token is self._token:
                self._snapshot._state.active_digest_token = None
            raise
        except BaseException:
            self.close()
            raise
        self._count += 1
        if self._count > MAX_TREE_ENTRIES:
            self.close()
            raise SnapshotError(
                f"content entries exceed the budget of {MAX_TREE_ENTRIES} entries"
            )
        if not isinstance(entry, GitEntry):
            self.close()
            raise SnapshotError("digests entries must all be GitEntry objects")
        try:
            object_id = self._snapshot._require_entry(entry)
        except BaseException:
            self.close()
            raise
        if entry.object_type != "blob":
            self.close()
            raise SnapshotError(
                f"object {entry.object_id} is a {entry.object_type}, not the blob "
                "its reference requires"
            )
        # M1 record, payload API row 2690-2703/1735-1759: retain admission, share modes.
        from receipt.protected_tree import classify_mode

        if not classify_mode(entry.mode, entry.object_type).regular:
            self.close()
            raise SnapshotError(
                f"tree entry has non-regular mode {entry.mode}: {entry.path}"
            )
        batch = self._snapshot._batch(digest_token=self._token)
        try:
            _object_type, size = batch.info(object_id, role="blob")
        except BaseException:
            self.close()
            raise
        per_blob_limit = min(self._per_blob, MAX_CONTENT_BLOB_BYTES)
        if size > per_blob_limit:
            self.close()
            raise SnapshotError(
                f"content blob {entry.path!r} exceeds the budget of "
                f"{per_blob_limit} bytes"
            )
        work = self._snapshot._state.work
        if self._charged + size > self._total:
            self.close()
            raise SnapshotError(
                f"content bytes exceed the budget of {self._total} bytes"
            )
        if self._snapshot._verification_total("content_bytes") + size > MAX_CONTENT_BYTES_TOTAL:
            self.close()
            raise SnapshotError(
                f"content bytes exceed the snapshot budget of "
                f"{MAX_CONTENT_BYTES_TOTAL} bytes"
            )
        digest = hashlib.sha256()

        def consume(chunk: bytes) -> None:
            digest.update(chunk)
            self._snapshot._charge_verification(
                "content_bytes",
                len(chunk),
                ceiling=MAX_CONTENT_BYTES_TOTAL,
                message=(
                    f"content bytes exceed the snapshot budget of "
                    f"{MAX_CONTENT_BYTES_TOTAL} bytes"
                ),
            )

        try:
            batch.consume(
                object_id,
                role="blob",
                limit=per_blob_limit,
                consumer=consume,
            )
        except BaseException:
            self.close()
            raise
        self._charged += size
        work.max_content_blob_bytes = max(work.max_content_blob_bytes, size)
        return entry, digest.hexdigest()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if not self._done:
            self._snapshot._abandon()
        if self._snapshot._state.active_digest_token is self._token:
            self._snapshot._state.active_digest_token = None

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


@dataclass(frozen=True)
class TreeSnapshot:
    """A frozen commit/tree identity with resources acquired only on entry."""

    git_dir: pathlib.Path
    commit: str
    tree: str
    object_format: str
    _state: _SnapshotState = field(repr=False, compare=False)

    @classmethod
    def select(
        cls,
        root: os.PathLike[str] | str,
        revision: str = "HEAD",
        *,
        verify_objects: bool = False,
        expect_commit: str | None = None,
        expect_tree: str | None = None,
    ) -> "TreeSnapshot":
        """Resolve and authenticate a commit and its root tree, then release Git.

        The plan's API sketch has no way to signal the conditional SHA1DC
        build preflight. The optional ``verify_objects`` keyword is the
        fail-closed plumbing choice. Expectations are checked commit first and
        tree second, before an entered snapshot can run another pass.

        Selection uses one temporary private config and one short-lived batch
        child under ``try/finally``. Non-repository setup and version children
        run from the applicable private directory. The long-lived child and
        its private directory are acquired only by :meth:`__enter__`.
        """

        if type(revision) is not str or not revision or "\0" in revision:
            raise SnapshotError("snapshot revision must be a non-empty string without NUL")
        if type(verify_objects) is not bool:
            raise SnapshotError("verify_objects must be a bool")
        try:
            selected_root = pathlib.Path(os.fspath(root)).resolve()
        except (TypeError, ValueError, OSError) as exc:
            raise SnapshotError(f"candidate repository path is invalid: {root!r}") from exc
        if "\n" in os.fspath(selected_root) or "\r" in os.fspath(selected_root):
            raise SnapshotError("repository top-level path contains a line break")

        global_bytes = _create_global_config(selected_root)
        with tempfile.TemporaryDirectory(prefix="receipt-snapshot-discovery-") as directory:
            private_directory = pathlib.Path(directory)
            global_path = private_directory / "global.gitconfig"
            global_path.write_bytes(global_bytes)
            environment = _git_environment(global_path)

            version_arguments = ["version"]
            if verify_objects:
                version_arguments.append("--build-options")
            version_result = _git_run(
                version_arguments,
                cwd=private_directory,
                environment=environment,
            )
            if version_result.returncode != 0:
                try:
                    root_is_directory = selected_root.is_dir()
                except OSError:
                    root_is_directory = False
                if not root_is_directory:
                    raise SnapshotError(
                        "candidate repository is missing or not a git repository: "
                        f"{selected_root}"
                    )
                raise SnapshotError(f"cannot run git version: {_first_error(version_result)}")
            version = _parse_version(version_result.stdout)
            if version < GIT_MIN_VERSION:
                floor = ".".join(str(part) for part in GIT_MIN_VERSION)
                raise SnapshotError(
                    f"Git {floor} or later is required for cat-file --batch-command"
                )
            if verify_objects:
                if b"SHA-1: SHA1_DC" not in version_result.stdout.splitlines():
                    raise SnapshotError(
                        "--verify-objects requires a Git build using SHA-1: SHA1_DC"
                    )
                if version < GIT_FSCK_NO_REFERENCES_MIN_VERSION:
                    raise SnapshotError(
                        "--verify-objects requires Git 2.50.0 or later for "
                        "fsck --no-references"
                    )

            discovery = _git_run(
                [
                    "-C",
                    os.fspath(selected_root),
                    "rev-parse",
                    "--show-toplevel",
                    "--absolute-git-dir",
                    "--git-common-dir",
                    "--show-object-format",
                ],
                cwd=None,
                environment=environment,
            )
            if discovery.returncode != 0:
                raise SnapshotError(
                    "candidate repository is missing or not a git repository: "
                    f"{selected_root}"
                )
            try:
                discovery_lines = discovery.stdout.decode(
                    "utf-8", errors="strict"
                ).splitlines()
            except UnicodeDecodeError as exc:
                raise SnapshotError("repository discovery output is not UTF-8") from exc
            if len(discovery_lines) != 4:
                raise SnapshotError("repository discovery output is malformed")
            top_text, git_dir_text, common_text, object_format = discovery_lines
            top_level = pathlib.Path(top_text).resolve()
            if top_level != selected_root:
                raise SnapshotError("root is not the top level of its repository")
            git_dir = pathlib.Path(git_dir_text)
            if not git_dir.is_absolute():
                git_dir = selected_root / git_dir
            git_dir = git_dir.resolve()
            common_dir = pathlib.Path(common_text)
            if not common_dir.is_absolute():
                common_dir = selected_root / common_dir
            common_dir = common_dir.resolve()
            cls._refuse_grafts_and_shallow(git_dir, common_dir)
            if object_format != "sha1":
                if object_format == "sha256":
                    raise SnapshotError(
                        "SHA-256 repositories are unsupported until a complete "
                        "reader fixture exists"
                    )
                raise SnapshotError(f"unsupported Git object format {object_format!r}")
            cls._refuse_alternates(git_dir, common_dir)

            config_result = _git_run(
                [
                    "-C",
                    os.fspath(selected_root),
                    "config",
                    "--list",
                    "--show-scope",
                    "--no-includes",
                    "-z",
                ],
                cwd=None,
                environment=environment,
            )
            if config_result.returncode != 0:
                raise SnapshotError(
                    f"cannot audit repository configuration: {_first_error(config_result)}"
                )
            config_records = _parse_config(config_result.stdout)
            _audit_config(config_records, selected_root)
            cls._refuse_grafts_and_shallow(git_dir, common_dir)
            cls._refuse_alternates(git_dir, common_dir)

            resolved = _git_run(
                _object_arguments(
                    git_dir,
                    [
                        "rev-parse",
                        "--verify",
                        "--end-of-options",
                        f"{revision}^{{commit}}",
                    ],
                ),
                cwd=None,
                environment=environment,
            )
            if resolved.returncode != 0:
                raise SnapshotError(f"cannot resolve commit '{revision}'")
            candidate = resolved.stdout.rstrip(b"\n")
            if (
                b"\n" in candidate
                or len(candidate) != hashlib.sha1().digest_size * 2
                or _OID_RE.fullmatch(candidate) is None
            ):
                raise SnapshotError(f"cannot resolve commit '{revision}'")
            candidate_oid = candidate.decode("ascii")

            cls._refuse_grafts_and_shallow(git_dir, common_dir)
            cls._refuse_alternates(git_dir, common_dir)
            with _BatchReader(
                git_dir,
                environment=environment,
                object_format=object_format,
            ) as batch:
                _kind, commit_size = batch.info(candidate_oid, role="commit")
                commit_payload = batch.consume(
                    candidate_oid,
                    role="commit",
                    limit=MAX_TREE_OBJECT_BYTES,
                    hold=True,
                )
                assert commit_payload is not None
                parsed_commit = _canonical_commit(
                    candidate_oid, commit_payload, object_format=object_format
                )
                if len(parsed_commit.parents) > MAX_ANCESTRY_COMMITS:
                    raise SnapshotError(
                        f"ancestry walk exceeds the budget of "
                        f"{MAX_ANCESTRY_COMMITS} commits"
                    )
                _kind, tree_size = batch.info(parsed_commit.tree, role="tree")
                if commit_size + tree_size > MAX_TREE_BYTES_TOTAL:
                    raise SnapshotError(
                        f"commit and tree bytes exceed the snapshot budget of "
                        f"{MAX_TREE_BYTES_TOTAL} bytes"
                    )
                tree_payload = batch.consume(
                    parsed_commit.tree,
                    role="tree",
                    limit=MAX_TREE_OBJECT_BYTES,
                    hold=True,
                )
                assert tree_payload is not None
                root_tree = _parse_raw_tree(
                    parsed_commit.tree, tree_payload, object_format=object_format
                )
                if len(root_tree) > MAX_TREE_ENTRIES:
                    raise SnapshotError(
                        f"tree walk exceeds the budget of {MAX_TREE_ENTRIES} entries"
                    )
                for parent in parsed_commit.parents:
                    batch.info(parent, role="commit")
                for raw in root_tree:
                    if raw.mode != b"160000":
                        batch.info(raw.oid, role=raw.object_type)

        if expect_commit is not None:
            expected_commit = _validate_expected_oid(
                expect_commit,
                label="commit",
                object_format=object_format,
            )
            if candidate_oid != expected_commit:
                raise SnapshotError(
                    f"commit {candidate_oid} is not the expected commit "
                    f"{expected_commit}"
                )
        if expect_tree is not None:
            expected_tree = _validate_expected_oid(
                expect_tree,
                label="tree",
                object_format=object_format,
            )
            if parsed_commit.tree != expected_tree:
                raise SnapshotError(
                    f"tree {parsed_commit.tree} is not the expected tree "
                    f"{expected_tree}"
                )

        work = SnapshotWork(
            tree_bytes=commit_size + tree_size,
            max_tree_object_bytes=max(commit_size, tree_size),
        )
        state = _SnapshotState(
            root=selected_root,
            common_dir=common_dir,
            revision=revision,
            version=version,
            config_records=config_records,
            global_config_bytes=global_bytes,
            verify_objects_ready=verify_objects,
            selected_commit=parsed_commit,
            root_tree=root_tree,
            work=work,
            work_pool=_WorkPool([work]),
            tree_cache={parsed_commit.tree: root_tree},
            commit_cache={candidate_oid: parsed_commit},
        )
        return cls(
            git_dir=git_dir,
            commit=candidate_oid,
            tree=parsed_commit.tree,
            object_format=object_format,
            _state=state,
        )

    @staticmethod
    def _repository_directories(
        git_dir: pathlib.Path, common_dir: pathlib.Path
    ) -> tuple[pathlib.Path, ...]:
        return tuple(dict.fromkeys((git_dir, common_dir)))

    @staticmethod
    def _repository_control_exists(path: pathlib.Path) -> bool:
        try:
            path.lstat()
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise SnapshotError(
                f"cannot inspect repository control path: {path}"
            ) from exc
        return True

    @classmethod
    def _refuse_grafts_and_shallow(
        cls, git_dir: pathlib.Path, common_dir: pathlib.Path
    ) -> None:
        for directory in cls._repository_directories(git_dir, common_dir):
            if cls._repository_control_exists(directory / "info" / "grafts"):
                raise SnapshotError("repository grafts are unsupported")
            if cls._repository_control_exists(directory / "shallow"):
                raise SnapshotError("shallow repositories are unsupported")

    @classmethod
    def _refuse_alternates(
        cls, git_dir: pathlib.Path, common_dir: pathlib.Path
    ) -> None:
        for directory in cls._repository_directories(git_dir, common_dir):
            if cls._repository_control_exists(
                directory / "objects" / "info" / "alternates"
            ):
                raise SnapshotError("alternate object databases are unsupported")

    def _reaudit_repository_files(self) -> None:
        """Recheck repository-control sentinels before another Git child."""

        self._refuse_grafts_and_shallow(self.git_dir, self._state.common_dir)
        self._refuse_alternates(self.git_dir, self._state.common_dir)

    def __enter__(self) -> "TreeSnapshot":
        if self._state.closed:
            raise SnapshotError("snapshot is closed")
        if self._state.entered:
            raise SnapshotError("snapshot is already entered")
        temporary: tempfile.TemporaryDirectory[str] | None = None
        try:
            temporary = tempfile.TemporaryDirectory(prefix="receipt-snapshot-")
            global_path = pathlib.Path(temporary.name, "global.gitconfig")
            global_path.write_bytes(self._state.global_config_bytes)
            global_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
            self._reaudit_repository_files()
            batch = _BatchReader(
                self.git_dir,
                environment=_git_environment(global_path),
                object_format=self.object_format,
            )
        except BaseException as caught:
            if temporary is not None:
                try:
                    temporary.cleanup()
                except BaseException as cleanup_error:
                    caught.add_note(
                        f"Snapshot startup cleanup also failed: {cleanup_error}"
                    )
            self._state.closed = True
            raise
        self._state.tempdir = temporary
        self._state.global_config = global_path
        self._state.batch = batch
        self._state.entered = True
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        _traceback: object,
    ) -> None:
        closing_errors: list[BaseException] = []
        try:
            if self._state.active_digest_token is not None:
                self._abandon()
            if self._state.batch is not None:
                try:
                    self._state.batch.close()
                except BaseException as caught:
                    closing_errors.append(caught)
            try:
                self._reaudit_repository_files()
            except BaseException as caught:
                closing_errors.append(caught)
            if self._state.global_config is not None:
                try:
                    completed = _git_run(
                        [
                            "-C",
                            os.fspath(self._state.root),
                            "config",
                            "--list",
                            "--show-scope",
                            "--no-includes",
                            "-z",
                        ],
                        cwd=None,
                        environment=_git_environment(self._state.global_config),
                    )
                    if completed.returncode != 0:
                        raise SnapshotError(
                            f"cannot re-audit repository configuration: "
                            f"{_first_error(completed)}"
                        )
                    records = _parse_config(completed.stdout)
                    if records != self._state.config_records:
                        raise SnapshotError(
                            "repository configuration changed during verification"
                        )
                    _audit_config(records, self._state.root)
                except BaseException as caught:
                    closing_errors.append(caught)
        finally:
            try:
                if self._state.tempdir is not None:
                    self._state.tempdir.cleanup()
            except BaseException as caught:
                closing_errors.append(caught)
            finally:
                self._state.batch = None
                self._state.tempdir = None
                self._state.global_config = None
                self._state.entered = False
                self._state.closed = True
        if closing_errors:
            if exc is not None:
                for closing_error in closing_errors:
                    exc.add_note(f"Snapshot close also failed: {closing_error}")
            else:
                primary, *additional = closing_errors
                for closing_error in additional:
                    primary.add_note(f"Snapshot close also failed: {closing_error}")
                raise primary

    @property
    def root(self) -> pathlib.Path:
        return self._state.root

    @property
    def common_dir(self) -> pathlib.Path:
        return self._state.common_dir

    @property
    def work(self) -> SnapshotWork:
        return self._state.work

    def _verification_total(self, field_name: str) -> int:
        pool = self._state.work_pool.root()
        return sum(getattr(work, field_name) for work in pool.works)

    def _charge_verification(
        self,
        field_name: str,
        amount: int,
        *,
        ceiling: int,
        message: str,
    ) -> None:
        if self._verification_total(field_name) + amount > ceiling:
            raise SnapshotError(message)
        work = self._state.work
        setattr(work, field_name, getattr(work, field_name) + amount)

    def _link_verification_work(self, other: "TreeSnapshot") -> None:
        """Make verification-wide budgets cumulative across a snapshot pair."""

        left = self._state.work_pool.root()
        right = other._state.work_pool.root()
        if left is right:
            return
        combined = (*left.works, *right.works)
        limits = (
            (
                "path_bytes",
                MAX_PATH_BYTES_TOTAL,
                f"tree paths exceed the snapshot budget of {MAX_PATH_BYTES_TOTAL} bytes",
            ),
            (
                "attribute_bytes",
                MAX_ATTRIBUTE_BYTES_TOTAL,
                f"attribute bytes exceed the snapshot budget of {MAX_ATTRIBUTE_BYTES_TOTAL} bytes",
            ),
            (
                "attribute_rules",
                MAX_ATTRIBUTE_RULES_TOTAL,
                f"attribute rules exceed the snapshot budget of {MAX_ATTRIBUTE_RULES_TOTAL} rules",
            ),
            (
                "attribute_match_work",
                MAX_ATTRIBUTE_MATCH_WORK,
                f"attribute matching exceeds the work budget of {MAX_ATTRIBUTE_MATCH_WORK} steps",
            ),
            (
                "content_bytes",
                MAX_CONTENT_BYTES_TOTAL,
                f"content bytes exceed the snapshot budget of {MAX_CONTENT_BYTES_TOTAL} bytes",
            ),
            (
                "materialized_bytes",
                MAX_MATERIALIZED_BYTES,
                f"materialized bytes exceed the budget of {MAX_MATERIALIZED_BYTES} bytes",
            ),
        )
        for field_name, ceiling, message in limits:
            if sum(getattr(work, field_name) for work in combined) > ceiling:
                raise SnapshotError(message)
        if right.attributes is not None:
            if left.attributes is None:
                left.attributes = right.attributes
            else:
                left.attributes.merge(right.attributes)
        left.works.extend(right.works)
        right.parent = left

    @property
    def batch_pid(self) -> int | None:
        batch = self._state.batch
        return batch.process.pid if batch is not None else None

    @property
    def temporary_directory(self) -> pathlib.Path | None:
        temporary = self._state.tempdir
        return pathlib.Path(temporary.name) if temporary is not None else None

    def _batch(self, *, digest_token: object | None = None) -> _BatchReader:
        if self._state.abandoned:
            raise SnapshotError("snapshot stream was abandoned")
        if (
            self._state.active_digest_token is not None
            and digest_token is not self._state.active_digest_token
        ):
            self._abandon()
            raise SnapshotError("snapshot stream was abandoned")
        if not self._state.entered or self._state.batch is None:
            raise SnapshotError("snapshot must be entered before object reads")
        if self._state.batch.abandoned:
            self._state.abandoned = True
            raise SnapshotError("snapshot stream was abandoned")
        return self._state.batch

    def _abandon(self) -> None:
        self._state.abandoned = True
        if self._state.batch is not None:
            self._state.batch.abandon()

    def _validate_oid(self, oid: str) -> str:
        width = hashlib.new(self.object_format).digest_size * 2
        if (
            type(oid) is not str
            or len(oid) != width
            or re.fullmatch(r"[0-9a-f]+", oid) is None
        ):
            raise SnapshotError(f"object name is not full lowercase hexadecimal: {oid!r}")
        return oid

    def _require_entry(self, entry: GitEntry) -> str:
        """Bind an entry argument to this snapshot before using its OID."""

        if type(entry) is not GitEntry:
            raise SnapshotError("blob entry must be a GitEntry")
        binding = entry._snapshot_token
        if (
            type(binding) is not _EntryBinding
            or binding.snapshot_token is not self._state.entry_token
            or any(
                type(value) is not str
                for value in (
                    entry.mode,
                    entry.object_type,
                    entry.object_id,
                    entry.path,
                )
            )
            or (
                entry.mode,
                entry.object_type,
                entry.object_id,
                entry.path,
            )
            != (
                binding.mode,
                binding.object_type,
                binding.object_id,
                binding.path,
            )
        ):
            raise SnapshotError("GitEntry does not belong to this snapshot")
        return self._validate_oid(entry.object_id)

    def header(self, oid: str) -> tuple[str, int]:
        """Return an object's type and size without requesting its payload."""

        return self._batch().info(self._validate_oid(oid))

    def _charge_tree_object(self, size: int) -> None:
        work = self._state.work
        if work.tree_bytes + size > MAX_TREE_BYTES_TOTAL:
            raise SnapshotError(
                f"tree and commit bytes exceed the snapshot budget of "
                f"{MAX_TREE_BYTES_TOTAL} bytes"
            )
        work.tree_bytes += size
        work.max_tree_object_bytes = max(work.max_tree_object_bytes, size)

    def _tree_object(self, oid: str) -> tuple[_RawTreeEntry, ...]:
        batch = self._batch()
        cached = self._state.tree_cache.get(oid)
        if cached is not None:
            return cached
        _kind, size = batch.info(oid, role="tree")
        if self._state.work.tree_bytes + size > MAX_TREE_BYTES_TOTAL:
            raise SnapshotError(
                f"tree and commit bytes exceed the snapshot budget of "
                f"{MAX_TREE_BYTES_TOTAL} bytes"
            )
        payload = batch.consume(
            oid, role="tree", limit=MAX_TREE_OBJECT_BYTES, hold=True
        )
        assert payload is not None
        self._charge_tree_object(size)
        parsed = _parse_raw_tree(oid, payload, object_format=self.object_format)
        if len(parsed) > MAX_TREE_ENTRIES:
            raise SnapshotError(
                f"tree walk exceeds the budget of {MAX_TREE_ENTRIES} entries"
            )
        for raw in parsed:
            if raw.mode != b"160000":
                batch.info(raw.oid, role=raw.object_type)
        self._state.tree_cache[oid] = parsed
        return parsed

    def _commit_object(
        self, oid: str, *, parent_budget: int | None = None
    ) -> _CommitObject:
        batch = self._batch()
        cached = self._state.commit_cache.get(oid)
        if cached is not None:
            return cached
        _kind, size = batch.info(oid, role="commit")
        if self._state.work.tree_bytes + size > MAX_TREE_BYTES_TOTAL:
            raise SnapshotError(
                f"tree and commit bytes exceed the snapshot budget of "
                f"{MAX_TREE_BYTES_TOTAL} bytes"
            )
        payload = batch.consume(
            oid, role="commit", limit=MAX_TREE_OBJECT_BYTES, hold=True
        )
        assert payload is not None
        self._charge_tree_object(size)
        if parent_budget is None:
            parent_budget = MAX_ANCESTRY_COMMITS
        parsed = _canonical_commit(
            oid,
            payload,
            object_format=self.object_format,
            parent_limit=parent_budget,
        )
        batch.info(parsed.tree, role="tree")
        if len(parsed.parents) > parent_budget:
            raise SnapshotError(
                f"ancestry walk exceeds the budget of "
                f"{MAX_ANCESTRY_COMMITS} commits"
            )
        # Every tree line reached by the ancestry walk is authenticated even
        # though parentage itself needs only the commit payload.
        self._tree_object(parsed.tree)
        for parent in parsed.parents:
            batch.info(parent, role="commit")
        self._state.commit_cache[oid] = parsed
        return parsed

    def _charge_walk_records(
        self, records: Sequence[_RawTreeEntry], count: list[int]
    ) -> None:
        count[0] += len(records)
        work = self._state.work
        work.tree_entries += len(records)
        work.max_tree_entries_in_walk = max(
            work.max_tree_entries_in_walk, count[0]
        )
        if count[0] > MAX_TREE_ENTRIES:
            raise SnapshotError(
                f"tree walk exceeds the budget of {MAX_TREE_ENTRIES} entries"
            )

    @staticmethod
    def _find_raw_entry(
        records: Sequence[_RawTreeEntry], component: bytes
    ) -> _RawTreeEntry | None:
        """Find an exact raw name in canonical Git order in logarithmic work."""

        for key in (component, component + b"/"):
            index = bisect_left(records, key, key=_raw_tree_sort_key)
            if index < len(records) and records[index].name == component:
                return records[index]
        return None

    @staticmethod
    # M1 record, path API row 2514-2542: raw argument grammar and budgets stay here.
    def _path_parts(path: str | bytes, *, allow_empty: bool) -> tuple[bytes, ...]:
        if type(path) is str:
            try:
                raw_path = _tree_path_encode(path)
            except UnicodeEncodeError as exc:
                raise SnapshotError(f"tree path cannot be encoded: {path!r}") from exc
        elif type(path) is bytes:
            raw_path = path
        else:
            raise SnapshotError(f"tree path must be str or bytes: {path!r}")
        if not raw_path and allow_empty:
            return ()
        if not raw_path or raw_path.startswith(b"/") or raw_path.endswith(b"/"):
            raise SnapshotError(f"tree path must be a relative non-empty path: {path!r}")
        if len(raw_path) > MAX_PATH_BYTES:
            raise SnapshotError(
                f"tree path exceeds the budget of {MAX_PATH_BYTES} bytes"
            )
        parts = tuple(raw_path.split(b"/"))
        if len(parts) > MAX_TREE_DEPTH + 1:
            raise SnapshotError(
                f"tree path exceeds the depth budget of {MAX_TREE_DEPTH}"
            )
        try:
            for part in parts:
                validate_component_bytes(part, label="tree path component")
        except NamePolicyError as exc:
            raise SnapshotError(str(exc)) from exc
        return parts

    def _public_entry(
        self, parts: tuple[bytes, ...], raw: _RawTreeEntry
    ) -> GitEntry:
        path_bytes = b"/".join(parts)
        self._charge_path_bytes(path_bytes)
        path_text = _tree_path_decode(path_bytes)
        mode = raw.display_mode
        object_type = raw.object_type
        binding = _EntryBinding(
            self._state.entry_token,
            mode,
            object_type,
            raw.oid,
            path_text,
        )
        return GitEntry(
            mode=mode,
            object_type=object_type,
            object_id=raw.oid,
            path=path_text,
            _snapshot_token=binding,
        )

    def _charge_path_bytes(self, path_bytes: bytes) -> None:
        """Charge one full logical path at the moment it is materialized."""

        size = len(path_bytes)
        if size > MAX_PATH_BYTES:
            raise SnapshotError(
                f"tree path exceeds the budget of {MAX_PATH_BYTES} bytes"
            )
        work = self._state.work
        self._charge_verification(
            "path_bytes",
            size,
            ceiling=MAX_PATH_BYTES_TOTAL,
            message=f"tree paths exceed the snapshot budget of {MAX_PATH_BYTES_TOTAL} bytes",
        )
        work.max_path_bytes = max(work.max_path_bytes, size)

    def _build_listing(
        self,
        tree_oid: str,
        *,
        depth: int,
        count: list[int],
    ) -> _TreeNode:
        if depth > MAX_TREE_DEPTH:
            raise SnapshotError(
                f"tree depth exceeds the budget of {MAX_TREE_DEPTH}"
            )
        records: list[_ListingRecord] = []
        raw_entries = self._tree_object(tree_oid)
        for raw in raw_entries:
            count[0] += 1
            self._state.work.tree_entries += 1
            self._state.work.max_tree_entries_in_walk = max(
                self._state.work.max_tree_entries_in_walk, count[0]
            )
            if count[0] > MAX_TREE_ENTRIES:
                raise SnapshotError(
                    f"tree walk exceeds the budget of {MAX_TREE_ENTRIES} entries"
                )
            child: _TreeNode | None = None
            if raw.mode != b"160000":
                self._batch().info(raw.oid, role=raw.object_type)
            if raw.mode == b"40000":
                child = self._build_listing(
                    raw.oid,
                    depth=depth + 1,
                    count=count,
                )
            records.append(_ListingRecord(raw=raw, child=child))
        return _TreeNode(tuple(records), tree_oid)

    def entry(self, path: str | bytes) -> GitEntry:
        """Look up one path by its exact component bytes."""

        self._batch()
        parts = self._path_parts(path, allow_empty=False)
        tree_oid = self.tree
        count = [0]
        for index, component in enumerate(parts):
            records = self._tree_object(tree_oid)
            self._charge_walk_records(records, count)
            raw = self._find_raw_entry(records, component)
            if raw is None:
                raise SnapshotError(
                    "tree entry does not exist: "
                    f"{_tree_path_decode(b'/'.join(parts))}"
                )
            last = index == len(parts) - 1
            if raw.mode != b"160000":
                self._batch().info(raw.oid, role=raw.object_type)
            if last:
                return self._public_entry(parts, raw)
            _check_tree_ancestor(parts, index, raw)
            tree_oid = raw.oid
        raise AssertionError("a non-empty path has at least one component")

    def entries(self, prefix: str | bytes = "") -> TreeListing:
        """Walk a subtree into a hierarchical listing under the walk budgets."""

        self._batch()
        parts = self._path_parts(prefix, allow_empty=True)
        if not parts:
            node = self._build_listing(self.tree, depth=0, count=[0])
            return TreeListing(self, (), node)
        tree_oid = self.tree
        count = [0]
        for index, component in enumerate(parts):
            records = self._tree_object(tree_oid)
            self._charge_walk_records(records, count)
            raw = self._find_raw_entry(records, component)
            if raw is None:
                return TreeListing(self, parts, _TreeNode((), None))
            last = index == len(parts) - 1
            if raw.mode != b"160000":
                self._batch().info(raw.oid, role=raw.object_type)
            if last:
                if raw.mode == b"40000":
                    node = self._build_listing(
                        raw.oid, depth=len(parts), count=count
                    )
                    return TreeListing(self, parts, node)
                return TreeListing(
                    self,
                    parts[:-1],
                    _TreeNode((_ListingRecord(raw=raw),), None),
                )
            _check_tree_ancestor(parts, index, raw)
            tree_oid = raw.oid
        raise AssertionError("a non-empty path has at least one component")

    def blob(self, entry: GitEntry, *, limit: int) -> bytes:
        """Return one authenticated blob payload under a required caller limit."""

        object_id = self._require_entry(entry)
        if type(limit) is not int or limit < 0:
            raise SnapshotError("blob limit must be a non-negative integer")
        if entry.object_type != "blob":
            raise SnapshotError(
                f"object {entry.object_id} is a {entry.object_type}, not the blob "
                "its reference requires"
            )
        # M1 record, payload API row 2690-2703/1735-1759: retain admission, share modes.
        from receipt.protected_tree import classify_mode

        if not classify_mode(entry.mode, entry.object_type).regular:
            raise SnapshotError(
                f"tree entry has non-regular mode {entry.mode}: {entry.path}"
            )
        payload = self._batch().consume(
            object_id,
            role="blob",
            limit=limit,
            hold=True,
        )
        assert payload is not None
        return payload

    def digests(
        self,
        entries: Iterable[GitEntry],
        *,
        per_blob: int = MAX_CONTENT_BLOB_BYTES,
        total: int = MAX_CONTENT_BYTES_TOTAL,
    ) -> Iterator[tuple[GitEntry, str]]:
        """Stream authenticated blobs and yield their SHA-256 digests."""

        if type(per_blob) is not int or per_blob < 0:
            raise SnapshotError("per_blob must be a non-negative integer")
        if type(total) is not int or total < 0:
            raise SnapshotError("total must be a non-negative integer")
        if isinstance(entries, (str, bytes, GitEntry)):
            raise SnapshotError("digests entries must be an iterable of GitEntry objects")
        self._batch()
        return _DigestIterator(self, entries, per_blob=per_blob, total=total)

    def changed_paths(self, base: "TreeSnapshot") -> set[str]:
        """Compare authenticated leaf OIDs and modes without reading blob bytes."""

        if not isinstance(base, TreeSnapshot):
            raise SnapshotError("changed_paths base must be a TreeSnapshot")
        if base.git_dir != self.git_dir or base.object_format != self.object_format:
            raise SnapshotError("candidate and base snapshots must share an object store")
        self._batch()
        base._batch()
        self._link_verification_work(base)
        candidate_entries = self.entries("").as_dict()
        base_entries = base.entries("").as_dict()
        changed: set[str] = set()
        for path in candidate_entries.keys() | base_entries.keys():
            candidate = candidate_entries.get(path)
            prior = base_entries.get(path)
            if (
                candidate is None
                or prior is None
                or candidate.mode != prior.mode
                or candidate.object_id != prior.object_id
            ):
                changed.add(path)
        return changed

    def parents(self, commit: str) -> tuple[str, ...]:
        """Return parents from an authenticated canonical commit object."""

        self._batch()
        return self._commit_object(self._validate_oid(commit)).parents

    def assert_ancestor(self, base: "TreeSnapshot") -> str:
        """Prove a selected base commit is in this candidate's parent graph.

        A symbolic base is selected exactly once by its own
        :meth:`TreeSnapshot.select` call. Requiring that entered snapshot
        prevents a moving ref from being resolved a second time and joins the
        verification-wide work budgets before either tree is consumed.
        """

        self._batch()
        if not isinstance(base, TreeSnapshot):
            raise SnapshotError("assert_ancestor base must be a TreeSnapshot")
        if base.git_dir != self.git_dir or base.object_format != self.object_format:
            raise SnapshotError("candidate and base snapshots must share an object store")
        base._batch()
        base_oid = base.commit
        stack = [self.commit]
        seen: set[str] = set()
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            work = self._state.work
            if work.ancestry_commits >= MAX_ANCESTRY_COMMITS:
                raise SnapshotError(
                    f"ancestry walk exceeds the budget of "
                    f"{MAX_ANCESTRY_COMMITS} commits"
                )
            work.ancestry_commits += 1
            commit = self._commit_object(
                current,
                parent_budget=MAX_ANCESTRY_COMMITS - work.ancestry_edges,
            )
            if current == base_oid:
                self._link_verification_work(base)
                self._state.ancestry_bases.add(base_oid)
                return base_oid
            if work.ancestry_edges + len(commit.parents) > MAX_ANCESTRY_COMMITS:
                raise SnapshotError(
                    f"ancestry walk exceeds the budget of "
                    f"{MAX_ANCESTRY_COMMITS} commits"
                )
            work.ancestry_edges += len(commit.parents)
            stack.extend(reversed(commit.parents))
        if self._state.revision == "HEAD":
            raise SnapshotError(
                f"base commit {base_oid} is not an ancestor of HEAD"
            )
        raise SnapshotError(
            f"base commit {base_oid} is not an ancestor of candidate commit "
            f"{self.commit}"
        )

    def verify_object_store(self, heads: Iterable[str]) -> ObjectStoreReport:
        """Run the bounded SHA1DC verification of the whole primary store."""

        self._batch()
        if not self._state.verify_objects_ready:
            raise SnapshotError(
                "verify_object_store requires select(..., verify_objects=True)"
            )
        if self._state.global_config is None:
            raise AssertionError("an entered snapshot has a private config")
        if self._state.object_store_attempted:
            raise SnapshotError("verify_object_store may be run only once per snapshot")
        if isinstance(heads, (str, bytes)):
            raise SnapshotError("verify_object_store heads must be an iterable of OIDs")
        try:
            iterator = iter(heads)
        except TypeError as exc:
            raise SnapshotError(
                "verify_object_store heads must be an iterable of OIDs"
            ) from exc
        supplied: list[str] = []
        for head in iterator:
            if len(supplied) == 2:
                raise SnapshotError(
                    "verify_object_store requires candidate and optional base heads"
                )
            supplied.append(self._validate_oid(head))
        resolved_heads = tuple(supplied)
        if not resolved_heads or resolved_heads[0] != self.commit:
            raise SnapshotError(
                "verify_object_store first head must be the selected candidate commit"
            )
        if self._state.ancestry_bases:
            heads_are_exact = (
                len(resolved_heads) == 2
                and resolved_heads[1] in self._state.ancestry_bases
            )
        else:
            heads_are_exact = resolved_heads == (self.commit,)
        if not heads_are_exact:
            raise SnapshotError(
                "verify_object_store heads must be exactly the resolved candidate and base"
            )
        self._state.object_store_attempted = True
        environment = _git_environment(self._state.global_config)
        self._reaudit_repository_files()
        counted = _git_run(
            _object_arguments(self.git_dir, ["count-objects", "-v"]),
            cwd=None,
            environment=environment,
        )
        if counted.returncode != 0:
            raise SnapshotError(
                f"cannot count the primary object database: {_first_error(counted)}"
            )
        values: dict[str, int] = {}
        try:
            count_lines = counted.stdout.decode(
                "ascii", errors="strict"
            ).splitlines()
        except UnicodeDecodeError as exc:
            raise SnapshotError("git count-objects output is malformed") from exc
        for line in count_lines:
            key, separator, value = line.partition(": ")
            if not separator or key in values:
                raise SnapshotError("git count-objects output is malformed")
            if key == "alternate":
                raise SnapshotError("alternate object databases are unsupported")
            if value.isdecimal():
                values[key] = int(value)
        required = {"count", "size", "in-pack", "size-pack"}
        if not required <= values.keys():
            raise SnapshotError("git count-objects output is malformed")
        objects = values["count"] + values["in-pack"]
        store_kib = values["size"] + values["size-pack"]
        if objects > MAX_FSCK_OBJECTS:
            raise SnapshotError(
                f"object database exceeds the budget of {MAX_FSCK_OBJECTS} objects"
            )
        if store_kib > MAX_STORE_KIB:
            raise SnapshotError(
                f"object database exceeds the budget of {MAX_STORE_KIB} KiB"
            )

        self._reaudit_repository_files()
        started = time.monotonic()
        checked = _git_run(
            _object_arguments(
                self.git_dir,
                [
                    "-c",
                    "core.commitGraph=false",
                    "fsck",
                    "--full",
                    "--no-dangling",
                    "--no-reflogs",
                    "--no-references",
                    "--no-progress",
                    *resolved_heads,
                ],
            ),
            cwd=None,
            environment=environment,
            output_limit=MAX_FSCK_OUTPUT_BYTES,
            seconds=MAX_FSCK_SECONDS,
        )
        elapsed = time.monotonic() - started
        if checked.returncode != 0:
            raise SnapshotError(
                "object database failed git's own verification: "
                f"{_first_error(checked)}"
            )
        return ObjectStoreReport(objects=objects, store_kib=store_kib, seconds=elapsed)

    # M1 record, row 2931-2950: exact lookup retains authentication and delegates ancestors.
    def _raw_entry_at(self, parts: tuple[bytes, ...]) -> _RawTreeEntry | None:
        tree_oid = self.tree
        count = [0]
        for index, component in enumerate(parts):
            records = self._tree_object(tree_oid)
            self._charge_walk_records(records, count)
            raw = self._find_raw_entry(records, component)
            if raw is None:
                return None
            if raw.mode != b"160000":
                self._batch().info(raw.oid, role=raw.object_type)
            if index == len(parts) - 1:
                return raw
            _check_tree_ancestor(parts, index, raw, protected=True)
            tree_oid = raw.oid
        return None

    def _attribute_rules(
        self, parts: tuple[bytes, ...]
    ) -> tuple[_AttributeRule, ...]:
        from receipt import protected_tree

        return protected_tree.load_attribute_rules(self, parts)

    def _attribute_step(self) -> None:
        from receipt import protected_tree

        return protected_tree._charge_attribute_work(self)

    def refuse_transforming_attributes(
        self, paths: Iterable[str | bytes | GitEntry]
    ) -> None:
        """Evaluate the fail-closed committed-attribute subset over paths.

        Only ``filter``, ``ident`` and ``working-tree-encoding`` transform raw
        blob bytes: their set and valued states refuse, while unset, absent
        and an explicit unspecified state are harmless. ``text`` and ``eol``
        are accepted in every state, and the built-in ``binary`` macro expands
        to ``-diff -merge -text``. Each path's final attribute states are
        computed independently under exact matching and ASCII-folded matching,
        with last-rule-wins precedence in each reading; a transform in either
        reading refuses, regardless of repository configuration. Git uses
        ``WM_CASEFOLD`` on case-insensitive clones, so the folded reading also
        catches transforms an exact reading would miss. An unsupported
        ``core.ignoreCase`` boolean still refuses at selection. No non-tree
        attribute source is consulted.
        """

        self._batch()
        if isinstance(paths, (str, bytes, GitEntry)):
            raise SnapshotError("attribute paths must be an iterable of paths")
        try:
            iterator = iter(paths)
        except TypeError as exc:
            raise SnapshotError("attribute paths must be an iterable of paths") from exc
        from receipt.protected_tree import refuse_attributes

        refuse_attributes(self, iterator)

    # M1 record, materialization argument row 3112-3141: bounded public admission stays.
    def materialize(
        self,
        prefixes: Iterable[str | bytes | pathlib.PurePosixPath],
        destination: os.PathLike[str] | str,
        *,
        repertoire: str,
    ) -> "Materialization":
        """Return an unentered private materialization; no path exists yet."""

        try:
            selected_repertoire = validate_repertoire(repertoire)
        except NamePolicyError as exc:
            raise SnapshotError(str(exc)) from exc
        if isinstance(prefixes, (str, bytes, pathlib.PurePath)):
            raise SnapshotError("materialization prefixes must be an iterable of paths")
        try:
            requested_list: list[str | bytes] = []
            for prefix in prefixes:
                if len(requested_list) >= MAX_TREE_ENTRIES:
                    raise SnapshotError(
                        f"materialization prefixes exceed the budget of "
                        f"{MAX_TREE_ENTRIES} entries"
                    )
                if type(prefix) is pathlib.PurePosixPath:
                    requested_list.append(prefix.as_posix())
                elif type(prefix) in {str, bytes}:
                    requested_list.append(prefix)
                else:
                    raise SnapshotError(
                        "materialization prefix must be str, bytes, or "
                        f"PurePosixPath: {prefix!r}"
                    )
            requested = tuple(requested_list)
        except TypeError as exc:
            raise SnapshotError("materialization prefixes must be iterable") from exc
        try:
            parent = pathlib.Path(os.fspath(destination))
        except (TypeError, ValueError) as exc:
            raise SnapshotError("materialization destination must be path-like") from exc
        return Materialization(self, requested, parent, selected_repertoire)


class Materialization:
    """A context-managed, screen-first private directory of selected blobs."""

    def __init__(
        self,
        snapshot: TreeSnapshot,
        prefixes: tuple[str | bytes, ...],
        destination: pathlib.Path,
        repertoire: str,
    ) -> None:
        from receipt.protected_tree import ProtectionPlan

        self._export_plan = ProtectionPlan.materialization(prefixes, repertoire=repertoire)
        self._snapshot = snapshot
        self._prefixes = prefixes
        self._destination = destination
        self._repertoire = repertoire
        self._path: pathlib.Path | None = None
        self._entries: dict[str, GitEntry] = {}
        self._entered = False
        self._closed = False

    @property
    def path(self) -> pathlib.Path:
        if self._path is None:
            raise SnapshotError("materialization must be entered before its path is used")
        return self._path

    @property
    def entries(self) -> dict[str, GitEntry]:
        if not self._entered:
            raise SnapshotError("materialization must be entered before entries are used")
        return dict(self._entries)

    def _deduplicated_prefixes(self) -> tuple[tuple[bytes, ...], ...]:
        from receipt.protected_tree import export_prefixes

        return export_prefixes(self._snapshot, self._prefixes)

    @staticmethod
    def _export_error(finding: object) -> SnapshotError:
        # Rendering stays at the public snapshot boundary; policy owns decisions.
        if finding.stage == "modes":
            return SnapshotError(
                f"base tree entry has non-regular mode {finding.mode}: {finding.path}"
            )
        return SnapshotError(finding.detail)

    def _selected_entries(self) -> dict[str, GitEntry]:
        from receipt.protected_tree import POLICY_VERSION, TreePolicy

        evaluator = TreePolicy(self._snapshot, policy_version=POLICY_VERSION,
                               work=self._snapshot.work)
        view = evaluator.evaluate(self._export_plan, stage="export-names")
        selected = evaluator.select_export(view, render=self._export_error)
        return dict(selected.entries_for(self._snapshot, use=self._export_plan.use,
                                         plan=self._export_plan))

    # M1 record, Materialization row: actual partial writes own byte charges and cleanup.
    def _write_chunk(self, handle: BinaryIO, chunk: bytes) -> None:
        written = 0
        view = memoryview(chunk)
        while written < len(chunk):
            count = handle.write(view[written:])
            if count is None or count <= 0:
                raise OSError("materialized file write made no progress")
            written += count
            self._snapshot._charge_verification(
                "materialized_bytes",
                count,
                ceiling=MAX_MATERIALIZED_BYTES,
                message=f"materialized bytes exceed the budget of {MAX_MATERIALIZED_BYTES} bytes",
            )

    def __enter__(self) -> "Materialization":
        if self._closed:
            raise SnapshotError("materialization is closed")
        if self._entered:
            raise SnapshotError("materialization is already entered")
        self._snapshot._batch()
        selected = self._selected_entries()
        try:
            destination_stat = self._destination.lstat()
        except OSError as exc:
            raise SnapshotError("materialization destination does not exist") from exc
        if not stat.S_ISDIR(destination_stat.st_mode) or stat.S_ISLNK(
            destination_stat.st_mode
        ):
            raise SnapshotError("materialization destination is not a real directory")

        created: pathlib.Path | None = None
        written_entries: dict[str, GitEntry] = {}
        local_total = 0
        try:
            created = pathlib.Path(
                tempfile.mkdtemp(
                    prefix=f"{self._snapshot.tree[:12]}-",
                    dir=self._destination,
                )
            )
            created.chmod(stat.S_IRWXU)
            # M1 record, materializer row: physical creation/modes/rehash remain writer duties.
            for relative, entry in sorted(selected.items()):
                batch = self._snapshot._batch()
                _kind, size = batch.info(entry.object_id, role="blob")
                if size > MAX_MATERIALIZED_BLOB_BYTES:
                    raise SnapshotError(
                        f"materialized blob {relative!r} exceeds the budget of "
                        f"{MAX_MATERIALIZED_BLOB_BYTES} bytes"
                    )
                work = self._snapshot.work
                if (
                    local_total + size > MAX_MATERIALIZED_BYTES
                    or self._snapshot._verification_total("materialized_bytes") + size > MAX_MATERIALIZED_BYTES
                ):
                    raise SnapshotError(
                        f"materialized bytes exceed the budget of "
                        f"{MAX_MATERIALIZED_BYTES} bytes"
                    )
                output = created.joinpath(*relative.split("/"))
                output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with output.open("xb") as handle:

                    def consume(chunk: bytes, *, _handle: BinaryIO = handle) -> None:
                        self._write_chunk(_handle, chunk)

                    batch.consume(
                        entry.object_id,
                        role="blob",
                        limit=MAX_MATERIALIZED_BLOB_BYTES,
                        consumer=consume,
                    )
                output.chmod(0o755 if entry.mode == "100755" else 0o644)
                local_total += size
                work.max_materialized_blob_bytes = max(
                    work.max_materialized_blob_bytes, size
                )
                written_entries[relative] = entry
        except BaseException as caught:
            if created is not None:
                try:
                    shutil.rmtree(created, ignore_errors=False)
                except BaseException as cleanup_error:
                    caught.add_note(
                        f"Materialization cleanup also failed: {cleanup_error}"
                    )
            self._closed = True
            raise
        self._path = created
        self._entries = written_entries
        self._entered = True
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        exc: BaseException | None,
        _traceback: object,
    ) -> None:
        cleanup_error: BaseException | None = None
        try:
            if self._path is not None:
                shutil.rmtree(self._path, ignore_errors=False)
        except BaseException as caught:
            cleanup_error = caught
        finally:
            self._entries = {}
            self._path = None
            self._entered = False
            self._closed = True
        if cleanup_error is not None:
            if exc is not None:
                exc.add_note(f"Materialization cleanup also failed: {cleanup_error}")
            else:
                raise cleanup_error

    @staticmethod
    # M1 record, anchor filename row 3367-3387: evidence serialization admission stays.
    def _exact_filename(value: object) -> str:
        if not isinstance(value, (str, os.PathLike)):
            raise SnapshotError(
                "anchor filenames must be str or os.PathLike when the "
                f"anchor-set digest is computed; got {type(value).__name__}"
            )
        try:
            decoded = os.fsdecode(value)
            result = decoded if type(decoded) is str else str.__str__(decoded)
        except Exception as exc:
            raise SnapshotError(
                "anchor filename could not be decoded to a pathname: "
                f"{type(value).__name__}"
            ) from exc
        if _SURROGATE_PAIR_RE.search(result):
            raise SnapshotError(
                "anchor filename spells an astral character as an explicit "
                "surrogate pair, which JSON parsing would rewrite; configure "
                f"the character directly: {result!r}"
            )
        return result

    def anchor_set_sha256(self, chain_spec: object) -> str:
        """Digest configured materialized anchor bytes in receipt-canonical JSON."""

        if not self._entered or self._path is None:
            raise SnapshotError(
                "materialization must be entered before anchor bytes are digested"
            )
        try:
            anchor_relative = getattr(chain_spec, "anchor_relative")
            producer = getattr(chain_spec, "producer_public_key_filename")
            anchors = getattr(chain_spec, "anchors")
        except Exception as exc:
            raise SnapshotError("chain_spec does not carry the configured anchor set") from exc
        if not isinstance(anchor_relative, pathlib.PurePosixPath):
            raise SnapshotError("chain_spec anchor_relative must be a PurePosixPath")
        if not isinstance(anchors, Mapping):
            raise SnapshotError("chain_spec anchors must be a mapping")
        configured = [producer]
        for anchor in anchors.values():
            try:
                configured.append(getattr(anchor, "filename"))
            except Exception as exc:
                raise SnapshotError("configured anchor does not carry a filename") from exc

        # M1 record, anchor rows 3414-3456: recheck physical bytes and JSON key identity.
        per_file: dict[str, str] = {}
        for supplied in configured:
            filename = self._exact_filename(supplied)
            relative = anchor_relative / filename
            if relative.is_absolute() or ".." in relative.parts:
                raise SnapshotError(
                    f"configured anchor filename leaves the anchor directory: {filename!r}"
                )
            relative_text = relative.as_posix()
            if relative_text not in self._entries:
                raise SnapshotError(
                    f"configured anchor was not materialized: {relative_text}"
                )
            path = self._path.joinpath(*relative.parts)
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise SnapshotError(
                    f"configured materialized anchor is unavailable: {relative_text}"
                ) from exc
            if not stat.S_ISREG(metadata.st_mode):
                raise SnapshotError(
                    f"configured materialized anchor is not regular: {relative_text}"
                )
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                while chunk := handle.read(_BATCH_CHUNK_BYTES):
                    digest.update(chunk)
            prior = per_file.get(filename)
            if prior is not None and prior != digest.hexdigest():
                raise SnapshotError(
                    f"anchor file {filename!r} bytes changed during verification"
                )
            per_file[filename] = digest.hexdigest()

        from receipt.canonical import canonical_sha256, utf16_sort_key

        sort_keys = [utf16_sort_key(name) for name in per_file]
        if len(set(sort_keys)) != len(sort_keys):
            raise SnapshotError(
                "two configured anchor filenames are distinct in Python but "
                "identical as JSON strings; the verdict cannot report them faithfully"
            )
        return canonical_sha256(dict(per_file))


__all__ = [
    "BATCH_KILL_REAP_SECONDS",
    "GIT_COMMANDS",
    "GIT_ENVIRONMENT_DROPPED",
    "GIT_ENVIRONMENT_DROPPED_UNDOCUMENTED",
    "GIT_FSCK_NO_REFERENCES_MIN_VERSION",
    "GIT_MIN_VERSION",
    "GitEntry",
    "MAX_ANCESTRY_COMMITS",
    "MAX_ATTRIBUTE_BYTES",
    "MAX_ATTRIBUTE_BYTES_TOTAL",
    "MAX_ATTRIBUTE_MATCH_WORK",
    "MAX_ATTRIBUTE_RULES_TOTAL",
    "MAX_ATTRIBUTE_STATES_PER_LINE",
    "MAX_CONTENT_BLOB_BYTES",
    "MAX_CONTENT_BYTES_TOTAL",
    "MAX_ENTRY_NAME_BYTES",
    "MAX_FSCK_OBJECTS",
    "MAX_FSCK_OUTPUT_BYTES",
    "MAX_FSCK_SECONDS",
    "MAX_GIT_OUTPUT_BYTES",
    "MAX_GIT_SECONDS",
    "MAX_MATERIALIZED_BLOB_BYTES",
    "MAX_MATERIALIZED_BYTES",
    "MAX_PATH_BYTES",
    "MAX_PATH_BYTES_TOTAL",
    "MAX_STORE_KIB",
    "MAX_TREE_BYTES_TOTAL",
    "MAX_TREE_DEPTH",
    "MAX_TREE_ENTRIES",
    "MAX_TREE_OBJECT_BYTES",
    "Materialization",
    "ObjectStoreReport",
    "SnapshotError",
    "SnapshotWork",
    "TreeListing",
    "TreeSnapshot",
]
'''
# END verbatim src/receipt/snapshot.py

# BEGIN verbatim 9dc1f85fc0e06cb58b73bad6d09da4c89ee9a4d6:src/receipt/protected_tree.py
FROZEN_SOURCE['src/receipt/protected_tree.py'] = r'''"""Authenticated name, shape and attribute evidence for receipt 0.7 M1.

Names, configured aliases and scoped DOS suffixes are evaluated only at the
caller's existing barriers. The snapshot still owns object authentication and
structural/admission charges. Shape stages consume admitted metadata at the
caller's barrier; export certification precedes writing. Attributes are lazy and
use the fixed v0.6 exact-plus-ASCII-fold policy, independent of Git settings.

The mapping and sibling compatibility adapters confer no payload authority.
Only TreePolicy, over an entered snapshot, can issue a ProtectedTreeView.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, fields, replace
from pathlib import PurePosixPath
from types import MappingProxyType
from weakref import WeakValueDictionary

from receipt import _names, snapshot

POLICY_VERSION = "v0.6"
NAME_STAGES = ("aliases", "names", "siblings", "suffixes")
SHAPE_STAGES = ("ancestors", "modes")
BINDING_STAGES = ("content-roots", "content")
EXPORT_STAGES = ("ancestors", "modes", "export-names")


class PolicyUseError(RuntimeError):
    """Internal misuse of authenticated evidence, never a repository refusal."""


def _paths(values: Iterable[str | PurePosixPath]) -> tuple[str, ...]:
    # Plans compile admitted configuration, not an alternative spec parser.
    result = tuple(p.as_posix() if isinstance(p, PurePosixPath) else p for p in values)
    if any(type(p) is not str for p in result):
        raise PolicyUseError("plan selectors must be admitted path strings")
    return result


@dataclass(frozen=True)
class ProtectionPlan:
    """Ordered, frozen obligations compiled from already admitted specs.

    Configuration admission and append surface classification remain with their
    callers. listing_scope names exactly the subtrees read at this barrier;
    ancestor_listing_scope selects immediate listings, not their descendants.
    Later-stage fields participate in identity even before they are evaluated.
    """

    repertoire: str = "portable"
    selected_prefixes: tuple[str, ...] = ()
    configured_alias_targets: tuple[str, ...] = ()
    ancestor_listing_scope: tuple[str, ...] = ()
    whole_tree_name_scope: bool = False
    content_roots: tuple[str, ...] = ()
    content_suffixes: tuple[str, ...] = ()
    exact_state_paths: tuple[str, ...] = ()
    exact_attested_paths: tuple[str, ...] = ()
    export_prefixes: tuple[str, ...] = ()
    attribute_target_selectors: tuple[str, ...] = ()
    anchor_origin: str = "tree"
    use: str = "chain-names"
    phase: str = "names"
    obligations: tuple[str, ...] = NAME_STAGES
    listing_scope: tuple[str, ...] = ("",)
    fold_whole_alias_paths: bool = False
    mode_roles: tuple[tuple[str, str], ...] = ()
    ancestor_paths: tuple[str, ...] = ()
    require_ancestors: bool = False
    # Preserve bytes/text argument spelling until the legacy enter-time admission.
    export_requests: tuple[str | bytes, ...] = ()

    def __post_init__(self) -> None:
        for item in fields(self):
            value = getattr(self, item.name)
            if item.name in {
                "selected_prefixes", "configured_alias_targets",
                "ancestor_listing_scope", "content_roots", "content_suffixes",
                "exact_state_paths", "exact_attested_paths", "export_prefixes",
                "attribute_target_selectors", "obligations", "listing_scope", "ancestor_paths",
            }:
                object.__setattr__(self, item.name, _paths(value))
        object.__setattr__(self, "export_requests", tuple(self.export_requests))
        roles = tuple((_paths((path,))[0], role) for path, role in self.mode_roles)
        if any(role not in MODE_ROLES for _, role in roles):
            raise PolicyUseError("unknown protected entry role")
        object.__setattr__(self, "mode_roles", roles)

    @classmethod
    def chain_names(
        cls, prefixes: tuple[PurePosixPath, ...], *, repertoire: str,
        release_directories: tuple[PurePosixPath, ...],
        alias_paths: tuple[str, ...] | None = None,
        use: str = "chain-names", anchor_origin: str = "tree",
    ) -> ProtectionPlan:
        """Compile the retained chain/append facade without re-admitting specs."""
        selected = _paths(prefixes)
        ancestors = tuple(dict.fromkeys(
            "/".join(relative.parts[:depth])
            for relative in prefixes for depth in range(len(relative.parts))
        ))
        return cls(
            repertoire=repertoire, selected_prefixes=selected,
            configured_alias_targets=selected if alias_paths is None else alias_paths,
            ancestor_listing_scope=ancestors, content_roots=_paths(release_directories),
            content_suffixes=(".json", ".sig", ".tsr"), export_prefixes=selected,
            fold_whole_alias_paths=alias_paths is not None,
            anchor_origin=anchor_origin, use=use,
        )

    @classmethod
    def materialization(cls, prefixes: tuple[str | bytes, ...], *, repertoire: str) -> ProtectionPlan:
        """Compile admitted collection arguments; path admission stays lazy."""
        return cls(repertoire=repertoire,
                   export_prefixes=tuple(snapshot._tree_path_decode(p) if type(p) is bytes else p
                                         for p in prefixes),
                   export_requests=prefixes, listing_scope=(), obligations=EXPORT_STAGES,
                   use="materialize", phase="export")

    @property
    def fingerprint(self) -> str:
        values = tuple((f.name, getattr(self, f.name)) for f in fields(self))
        return hashlib.sha256(repr(values).encode("utf-8", "surrogateescape")).hexdigest()


@dataclass(frozen=True)
class Finding:
    """One condition and compact witnesses at a nested execution position.

    Primitive diagnostics retain their exact original text alongside operation,
    input and context. Alias/collision/suffix findings retain spelling witnesses;
    their caller, not this record, chooses public words and exception classes.
    """

    kind: str
    stage: str
    position: tuple[int, ...]
    path: str = ""
    raw_path: bytes | None = None
    parent: str = ""
    name: str = ""
    other_name: str = ""
    target: str = ""
    prefix: str = ""
    suffixes: tuple[str, ...] = ()
    operation: str = ""
    detail: str = ""
    mode: str = ""
    object_type: str = ""
    role: str = ""
    source: str = ""
    line: int = 0


MODE_ROLES = frozenset(("release-leaf", "state-leaf", "manifest-child", "ancestor", "export-leaf", "attested-leaf"))


@dataclass(frozen=True)
class ModeFact:
    """Object/leaf classification, independent of a caller's refusal text."""

    mode: str
    object_type: str
    shape: str

    @property
    def regular(self) -> bool:
        return self.shape in {"regular", "executable"}

    @property
    def directory(self) -> bool:
        return self.shape in {"tree", "empty-tree"}

    def finding(self, path: str, role: str, *, position: tuple[int, ...] = ()) -> Finding | None:
        if role not in MODE_ROLES:
            raise PolicyUseError("unknown protected entry role")
        if self.directory if role == "ancestor" else self.regular:
            return None
        kind = ("missing" if self.shape == "missing" else
                "symlink" if self.shape == "symlink" else
                "non-directory" if role == "ancestor" else "non-regular")
        return Finding(kind, "modes", position, path=path,
                       raw_path=path.encode("utf-8", "surrogateescape"),
                       parent=path.rpartition("/")[0], name=path.rpartition("/")[2],
                       mode=self.mode, object_type=self.object_type, role=role)


def classify_mode(mode: str, object_type: str, *, empty: bool = False) -> ModeFact:
    """Classify already authenticated metadata; never probe a Git object."""
    shapes = {("100644", "blob"): "regular", ("100755", "blob"): "executable",
              ("120000", "blob"): "symlink", ("160000", "commit"): "gitlink",
              ("040000", "tree"): "empty-tree" if empty else "tree",
              ("", ""): "missing"}
    return ModeFact(mode, object_type, shapes.get((mode, object_type), "object-type"))


def ancestor_finding(target: str, prefix: str, mode: str, object_type: str,
                     *, position: tuple[int, ...] = ()) -> Finding | None:
    """One reached component, also used by the reader's three walk facades.

    Missing witnesses keep both the requested path and first absent component.
    The reader decides whether absence is optional at its existing barrier.
    """
    fact = classify_mode(mode, object_type)
    finding = fact.finding(prefix, "ancestor", position=position)
    if finding is None:
        return None
    return replace(finding, stage="ancestors", target=target, prefix=prefix)


@dataclass(frozen=True)
class ShapeWork:
    mode_classifications: int = 0
    ancestor_steps: int = 0
    mode_cache_entries: int = 0
    ancestor_cache_entries: int = 0


class _ShapeFacts:
    def __init__(self):
        self.modes: dict[tuple[str, str, str, bool], ModeFact] = {}
        self.ancestors: dict[str, Finding | None] = {}
        self.steps = 0

    @property
    def work(self) -> ShapeWork:
        return ShapeWork(len(self.modes), self.steps, len(self.modes), len(self.ancestors))

    def mode(self, path: str, entry: snapshot.GitEntry | None, *, empty: bool = False) -> ModeFact:
        mode, kind = (entry.mode, entry.object_type) if entry is not None else ("", "")
        return self.metadata(path, mode, kind, empty=empty)

    def metadata(self, path: str, mode: str, kind: str, *, empty: bool = False) -> ModeFact:
        key = path, mode, kind, empty
        if key not in self.modes:
            self.modes[key] = classify_mode(mode, kind, empty=empty)
        return self.modes[key]

    def ancestor(self, target: str, entries: Mapping[str, snapshot.GitEntry]) -> Finding | None:
        if target not in self.ancestors:
            result = None
            parts = target.split("/")
            for depth in range(1, len(parts)):
                self.steps += 1
                prefix = "/".join(parts[:depth])
                entry = entries.get(prefix)
                fact = self.mode(prefix, entry)
                finding = fact.finding(prefix, "ancestor", position=(depth,))
                if finding is not None:
                    result = replace(finding, stage="ancestors", target=target, prefix=prefix)
                    break
            self.ancestors[target] = result
        return self.ancestors[target]



def regular_entries(entries: Mapping[str, snapshot.GitEntry], paths: Iterable[str],
                    *, facts: _ShapeFacts | None = None) -> tuple[snapshot.GitEntry, ...]:
    """Select regular metadata without requiring or granting payload authority."""
    facts = facts or _ShapeFacts()
    return tuple(entries[path] for path in paths if facts.mode(path, entries[path]).regular)


def export_prefixes(subject: snapshot.TreeSnapshot,
                    prefixes: Iterable[str | bytes]) -> tuple[tuple[bytes, ...], ...]:
    """Legacy supplied-path charges precede prefix deduplication."""
    parts: set[tuple[bytes, ...]] = set()
    for prefix in prefixes:
        parsed = subject._path_parts(prefix, allow_empty=True)
        subject._charge_path_bytes(b"/".join(parsed))
        parts.add(parsed)
    kept: list[tuple[bytes, ...]] = []
    for candidate in sorted(parts):
        if kept and candidate[:len(kept[-1])] == kept[-1]:
            continue
        kept.append(candidate)
    return tuple(kept)


@dataclass(frozen=True)
class ExportWork:
    """Actual export work, independent of the retained reader admission ledger."""

    prefixes: int = 0
    leaves: int = 0
    components: int = 0
    directory_records: int = 0


@dataclass(frozen=True)
class NameWork:
    """Actual computation, distinct from the public SnapshotWork ledger."""

    folds: int = 0
    alias_steps: int = 0
    scope_steps: int = 0
    sibling_steps: int = 0
    suffix_checks: int = 0
    fold_index_entries: int = 0
    alias_index_nodes: int = 0


class _Refusal(Exception):
    def __init__(self, finding: Finding):
        self.finding = finding


class _SiblingCollision(_names.NamePolicyError):
    def __init__(self, message: str, *, name: str, other: str, ordinal: int,
                 duplicate: bool):
        super().__init__(message)
        self.name, self.other, self.ordinal = name, other, ordinal
        self.duplicate = duplicate


@dataclass
class _AliasNode:
    children: dict[str, _AliasNode] = field(default_factory=dict)
    # Earliest target, then earliest target with a different exact prefix.
    first: tuple[int, str, tuple[str, ...]] | None = None
    second: tuple[int, str, tuple[str, ...]] | None = None
    continuing: int | None = None

    def match(self, key: str) -> _AliasNode | None:
        return self.children.get(key)

    def add(self, witness: tuple[int, str, tuple[str, ...]]) -> None:
        if self.first is None:
            self.first = witness
        elif self.second is None and witness[2] != self.first[2]:
            self.second = witness

    def alias(self, exact: tuple[str, ...]):
        return self.second if self.first is not None and self.first[2] == exact else self.first


class _NameFacts:
    """Private bounded component cache and shared name algorithms.

    Each distinct supplied component is folded at most once, including failures.
    Trie nodes grow with unique configured components; each node stores two
    witnesses rather than all colliding pairs. No new admission ceiling is used.
    """

    def __init__(self) -> None:
        self.folds: dict[str, str | _names.NamePolicyError] = {}
        self.full_folds: dict[str, str] = {}
        self.suffix_index: dict[tuple[str, tuple[str, ...]], bool] = {}
        self.counts = dict(folds=0, alias_steps=0, scope_steps=0,
                           sibling_steps=0, suffix_checks=0, alias_index_nodes=0)

    @property
    def work(self) -> NameWork:
        return NameWork(**self.counts, fold_index_entries=len(self.folds))

    def fold(self, name: str) -> str:
        if name not in self.folds:
            self.counts["folds"] += 1
            try:
                self.folds[name] = _names.ascii_fold_text(name)
            except _names.NamePolicyError as exc:
                self.folds[name] = _names.NamePolicyError(str(exc))
        value = self.folds[name]
        if isinstance(value, _names.NamePolicyError):
            raise _names.NamePolicyError(str(value))
        return value

    def folded_parts(self, path: str) -> tuple[str, ...]:
        return tuple(self.fold(part) for part in path.split("/"))

    def full_fold(self, path: str) -> str:
        if path not in self.full_folds:
            self.full_folds[path] = "/".join(self.folded_parts(path))
        return self.full_folds[path]

    def carries_suffix(self, path: str, suffixes: tuple[str, ...]) -> bool:
        return has_folded_suffix(self.full_fold(path), tuple(self.full_fold(s) for s in suffixes))

    def short_suffix(self, name: str, suffixes: tuple[str, ...]) -> bool:
        key = name, suffixes
        if key not in self.suffix_index:
            self.counts["suffix_checks"] += 1
            self.suffix_index[key] = _names.short_name_carries_pinned_suffix(name, suffixes)
        return self.suffix_index[key]

    def path_fold(self, path: str, *, operation: str,
                  position: tuple[int, ...]) -> tuple[str, ...]:
        return tuple(self.primitive(
            operation, lambda: self.fold(part), stage="aliases",
            position=(*position, depth), path=path, name=part,
        ) for depth, part in enumerate(path.split("/"), start=1))

    def primitive(self, operation: str, call: Callable, *, stage: str,
                  position: tuple[int, ...], path: str, name: str = ""):
        try:
            return call()
        except _names.NamePolicyError as exc:
            try:
                raw_path = path.encode("utf-8", "surrogateescape")
            except UnicodeEncodeError:
                # A compatibility mapping can contain text that cannot be Git
                # bytes at all. Preserve its original primitive refusal.
                raw_path = None
            raise _Refusal(Finding(
                "name", stage, position, path=path,
                raw_path=raw_path, name=name,
                parent=path.rpartition("/")[0], operation=operation, detail=str(exc),
            )) from exc

    def aliases(self, entries: Mapping[str, snapshot.GitEntry], plan: ProtectionPlan) -> None:
        root = _AliasNode()
        # Supplied target order is an earlier barrier than any listed entry.
        seen_targets: set[str] = set()
        for ordinal, path in enumerate(plan.configured_alias_targets):
            if path in seen_targets:
                continue
            seen_targets.add(path)
            exact = tuple(path.split("/"))
            folded = self.path_fold(path, operation="target-fold", position=(0, ordinal))
            node = root
            for depth, key in enumerate(folded, start=1):
                if node.continuing is None:
                    node.continuing = ordinal
                if key not in node.children:
                    node.children[key] = _AliasNode()
                    self.counts["alias_index_nodes"] += 1
                node = node.children[key]
                node.add((ordinal, path, exact[:depth]))

        for ordinal, listed in enumerate(sorted(
            entries, key=lambda path: (entries[path].mode == "040000", path),
        )):
            parts = tuple(listed.split("/"))
            folded = self.path_fold(
                listed, operation="whole-path-fold", position=(1, ordinal, 0),
            ) if plan.fold_whole_alias_paths else ()
            node = root
            winner: tuple[int, int, str, tuple[str, ...]] | None = None
            for depth, part in enumerate(parts, start=1):
                if not node.children:
                    break
                # A prior alias would fold its full diagnostic before the
                # legacy traversal could reach a later, unfoldable component.
                try:
                    key = folded[depth - 1] if folded else self.primitive(
                        "reached-component-fold", lambda: self.fold(part), stage="aliases",
                        position=(1, ordinal, 1, node.continuing, depth, 0),
                        path=listed, name=part,
                    )
                except _Refusal:
                    if winner is not None and winner[0] <= node.continuing:
                        self.path_fold(listed, operation="diagnostic-fold",
                            position=(1, ordinal, 1, winner[0], winner[1], 1))
                    raise
                self.counts["alias_steps"] += 1
                child = node.match(key)
                if child is None:
                    break
                node = child
                witness = node.alias(parts[:depth])
                if witness is not None:
                    candidate = (witness[0], depth, witness[1], witness[2])
                    if winner is None or candidate[:2] < winner[:2]:
                        winner = candidate
            if winner is not None:
                target_ordinal, depth, target, exact = winner
                position = (1, ordinal, 1, target_ordinal, depth, 1)
                self.path_fold(listed, operation="diagnostic-fold", position=position)
                raise _Refusal(Finding(
                    "configured-alias", "aliases", position, path=listed,
                    raw_path=listed.encode("utf-8", "surrogateescape"),
                    target=target, prefix="/".join(exact),
                ))

    def in_roots(self, path: str, roots: set[str], *, descendants_only: bool = False) -> bool:
        parts = path.split("/")
        for depth in range(len(parts) if descendants_only else len(parts) + 1):
            self.counts["scope_steps"] += 1
            if "/".join(parts[:depth]) in roots:
                return True
        return False

    def scoped(self, entries: Mapping[str, snapshot.GitEntry], plan: ProtectionPlan) -> tuple[str, ...]:
        ancestors = set(plan.ancestor_listing_scope)
        selected = set(plan.selected_prefixes)
        return tuple(path for path in sorted(entries) if (
            plan.whole_tree_name_scope or path.rpartition("/")[0] in ancestors
            or self.in_roots(path, selected)
        ))

    def names(self, paths: tuple[str, ...], plan: ProtectionPlan) -> None:
        binding = plan.phase == "binding"
        for ordinal, path in enumerate(paths):
            name = path.rpartition("/")[2]
            validate = _names.validate_component_text
            label = f"tree entry {path!r}"
            if binding:
                # Retain the renderer and late primitive hook at the corpus
                # boundary. The order and all decisions belong to this stage.
                from receipt import corpus
                label = f"tree entry {corpus._quoted(path)}"
                validate = corpus.validate_component_text
            operations = (
                ("local-fold", lambda: self.fold(name)),
                ("binding-portable" if binding and plan.repertoire == "portable" else "component",
                 lambda: (_names.assert_portable_name(name, label)
                    if plan.repertoire == "portable" else
                    validate(name, repertoire=plan.repertoire, label=label))),
            )
            if binding and plan.repertoire != "portable":
                operations = operations[::-1]
            for step, (operation, call) in enumerate(operations):
                self.primitive(operation, call, stage="names", position=(ordinal, step),
                               path=path, name=name)

    def siblings(self, names: Iterable[bytes | str], *, repertoire: str,
                 materializing: bool, label: str) -> None:
        # M1 record, shared name primitive row 323-386: one ordered decision loop.
        def counted_names():
            for value in names:
                self.counts["sibling_steps"] += 1
                yield value

        _names._screen_sibling_names(
            counted_names(), repertoire=repertoire, materializing=materializing,
            label=label, fold=self.fold, collision=_SiblingCollision,
        )

    def sibling_paths(self, paths: tuple[str, ...], plan: ProtectionPlan) -> None:
        by_directory: dict[str, list[str]] = {}
        for path in paths:
            directory, _, name = path.rpartition("/")
            by_directory.setdefault(directory, []).append(name)
        for ordinal, (directory, names) in enumerate(sorted(by_directory.items())):
            try:
                self.siblings(
                    names, repertoire=plan.repertoire, materializing=False,
                    label=f"tree directory {directory or '.'!r}",
                )
            except _SiblingCollision as exc:
                path = f"{directory}/{exc.name}" if directory else exc.name
                raise _Refusal(Finding(
                    "duplicate" if exc.duplicate else "sibling-alias", "siblings",
                    (ordinal, exc.ordinal), path=path,
                    raw_path=path.encode("utf-8", "surrogateescape"),
                    parent=directory, name=exc.name, other_name=exc.other,
                    operation="siblings", detail=str(exc),
                )) from exc
            except _names.NamePolicyError as exc:
                raise _Refusal(Finding(
                    "name", "siblings", (ordinal,), path=directory,
                    operation="siblings", detail=str(exc),
                )) from exc

    def suffixes(self, paths: tuple[str, ...], plan: ProtectionPlan) -> None:
        if plan.repertoire != "portable":
            return
        roots = set(plan.content_roots)
        for ordinal, path in enumerate(paths):
            if not self.in_roots(path, roots, descendants_only=True):
                continue
            name = path.rpartition("/")[2]
            if not self.fold(name).endswith(plan.content_suffixes) and (
                self.short_suffix(name, plan.content_suffixes)
            ):
                raise _Refusal(Finding(
                    "short-suffix", "suffixes", (ordinal,), path=path,
                    raw_path=path.encode("utf-8", "surrogateescape"),
                    parent=path.rpartition("/")[0], name=name,
                    suffixes=plan.content_suffixes,
                ))


def index_children(entries: Mapping[str, snapshot.GitEntry]) -> dict[str, dict[str, snapshot.GitEntry]]:
    """Index each authenticated entry's immediate parent, retaining empty trees."""
    children: dict[str, dict[str, snapshot.GitEntry]] = {}
    for path, entry in entries.items():
        parent, _, name = path.rpartition("/")
        children.setdefault(parent, {})[name] = entry
        if entry.mode == "040000":
            children.setdefault(path, {})
    return children


class _NameRun:
    def __init__(self, entries: Mapping[str, snapshot.GitEntry], plan: ProtectionPlan,
                 facts: _NameFacts, shapes: _ShapeFacts | None = None):
        self.entries = entries
        self.children = index_children(entries)
        self.shapes = shapes or _ShapeFacts()
        self.selected_paths: tuple[str, ...] | None = None
        self.plan = plan
        self.attribute_outcomes: dict[bytes, AttributeOutcome] = {}
        self.facts = facts
        self.completed: set[str] = set()
        self.findings: list[Finding] = []
        self.paths: tuple[str, ...] | None = None
        self.mode_facts: dict[tuple[str, str], ModeFact] = {}
        self.raw_listings: dict[str, tuple[snapshot._RawTreeEntry, ...]] = {}
        self.tree_ids: dict[str, str | None] = {}
        self.export_siblings: dict[tuple[bytes, ...], set[bytes]] = {}

    def evaluate(self, stage: str) -> None:
        if stage not in NAME_STAGES:
            raise NotImplementedError(f"protected-tree stage {stage!r} belongs to a later migration")
        for current in NAME_STAGES[:NAME_STAGES.index(stage) + 1]:
            if current not in self.plan.obligations or current in self.completed:
                continue
            if self.findings:
                return
            try:
                if current == "aliases":
                    self.facts.aliases(self.entries, self.plan)
                else:
                    if self.paths is None:
                        self.paths = self.facts.scoped(self.entries, self.plan)
                    if current == "names":
                        self.facts.names(self.paths, self.plan)
                    elif current == "siblings":
                        sibling_paths = self.paths
                        if self.plan.phase == "binding":
                            sibling_paths = tuple(
                                (directory + "/" if directory else "") + name
                                for directory in sorted({"", *(p for p, e in self.entries.items()
                                                              if e.mode == "040000")})
                                for name in sorted(self.children.get(directory, {})))
                        self.facts.sibling_paths(sibling_paths, self.plan)
                    else:
                        self.facts.suffixes(self.paths, self.plan)
            except _Refusal as exc:
                self.findings.append(exc.finding)
                return
            self.completed.add(current)


    def binding(self, stage: str) -> None:
        """Select root spelling or content facts in binding's per-root order."""
        if stage in self.completed or self.findings:
            return
        found: list[str] = []
        try:
            for root_ordinal, root in enumerate(self.plan.content_roots):
                if stage == "content-roots":
                    parent = ""
                    for depth, component in enumerate(root.split("/")):
                        for name in sorted(self.children.get(parent, {})):
                            if name != component and self.facts.full_fold(name) == self.facts.full_fold(component):
                                raise _Refusal(Finding("content-root-alias", stage, (root_ordinal, depth),
                                                      name=name, target=component))
                        exact = (parent + "/" if parent else "") + component
                        if not self.shapes.mode(exact, self.entries.get(exact)).directory:
                            break
                        parent = exact
                    continue
                root_fact = self.shapes.mode(root, self.entries.get(root))
                self.mode_facts[root, "ancestor"] = root_fact
                if not root_fact.directory:
                    raise _Refusal(Finding("content-root-missing" if root_fact.shape == "missing"
                        else "content-root-mode", stage, (root_ordinal, 0), path=root))
                for ordinal, path in enumerate(sorted(self.entries)):
                    if not path.startswith(root + "/"):
                        continue
                    entry = self.entries[path]
                    fact = self.shapes.mode(path, entry)
                    position = (root_ordinal, 1, ordinal)
                    if fact.mode == "160000":
                        raise _Refusal(Finding("content-gitlink", stage, (*position, 0), path=path))
                    if not self.facts.carries_suffix(path, self.plan.content_suffixes):
                        if self.plan.repertoire == "portable" and self.facts.short_suffix(
                            path.rpartition("/")[2], self.plan.content_suffixes):
                            raise _Refusal(Finding("content-short-suffix", stage, (*position, 1), path=path))
                        continue
                    self.mode_facts[path, "attested-leaf"] = fact
                    if not fact.regular:
                        raise _Refusal(Finding("content-symlink" if fact.mode == "120000"
                            else "content-mode", stage, (*position, 2), path=path,
                            mode=fact.mode, object_type=fact.object_type))
                    found.append(path)
        except _Refusal as exc:
            self.findings.append(exc.finding)
            return
        except _names.NamePolicyError as exc:
            self.findings.append(Finding("name", stage, (), detail=str(exc)))
            return
        if stage == "content":
            self.selected_paths = tuple(dict.fromkeys(found))
        self.completed.add(stage)


def evaluate_binding_mapping(entries: Mapping[str, snapshot.GitEntry], plan: ProtectionPlan,
                             *, stage: str, by_directory=None) -> _NameRun:
    """Legacy mapping evidence shares decisions but cannot certify payload reads."""
    run = _NameRun(entries, plan, _NameFacts())
    if by_directory is not None:
        run.children = {p: dict(children) for p, children in by_directory.items()}
    if stage in NAME_STAGES:
        run.evaluate(stage)
    else:
        run.binding(stage)
    return run


def folded_path_index(entries: Mapping[str, snapshot.GitEntry], *,
                      facts: _NameFacts | None = None) -> dict[str, str]:
    """Retain the first sorted exact witness for each lazily requested fold key."""
    facts = facts or _NameFacts()
    folded: dict[str, str] = {}
    for path in sorted(entries):
        folded.setdefault(facts.full_fold(path), path)
    return folded


def read_binding_listing(subject: snapshot.TreeSnapshot, *, evaluator=None):
    """Admit binding's exact reader call before creating a standalone evaluator.

    Declaration prerequisites belong to the caller. This explicit read preserves
    lifecycle refusals at entries(), as well as repeated listing/path charges
    when a custody evaluator already holds the same immutable metadata.
    Subclass listings remain mapping evidence, without policy-view authority.
    """
    if evaluator is not None and evaluator.snapshot is not subject:
        raise PolicyUseError("binding evaluator has a different subject")
    listing = subject.entries("")
    entries = listing.as_dict(include_trees=True)
    if evaluator is None and type(subject) is not snapshot.TreeSnapshot:
        return None, entries
    evaluator = evaluator or TreePolicy(subject, policy_version=POLICY_VERSION, work=subject.work)
    evaluator._entries.update(entries)
    evaluator._scopes[""] = listing.tree_oid
    evaluator._empty_roots[""] = not listing._node.records
    return evaluator, entries


def has_folded_suffix(path: str, suffixes: Iterable[str]) -> bool:
    """Match folded suffixes in caller order without pre-consuming a lazy input."""
    return any(path.endswith(suffix) for suffix in suffixes)


def folded_parts(path: str) -> tuple[str, ...]:
    """Compatibility primitive for the retained chain helper import path."""
    return _NameFacts().folded_parts(path)


def evaluate_name_mapping(entries: Mapping[str, snapshot.GitEntry], plan: ProtectionPlan) -> Finding | None:
    """Compatibility evidence only: supplied mappings never certify payloads."""
    run = _NameRun(entries, plan, _NameFacts())
    run.evaluate("suffixes")
    return run.findings[0] if run.findings else None


def screen_siblings(names: Iterable[bytes | str], *, repertoire: str,
                    materializing: bool = False, label: str = "tree directory") -> None:
    """Shared implementation of the snapshot's legacy local-name screen."""
    try:
        _NameFacts().siblings(names, repertoire=repertoire, materializing=materializing, label=label)
    except _SiblingCollision as exc:
        # The old helper exposes exactly NamePolicyError, not an internal type.
        raise _names.NamePolicyError(str(exc)) from exc


@dataclass(frozen=True)
class DeclarationObligations:
    """Parsed declaration order and the caller's live alias-index ceiling."""

    paths: tuple[str, ...]
    alias_index_limit: int

    def __post_init__(self):
        object.__setattr__(self, "paths", _paths(self.paths))


def evaluate_declarations(obligations: DeclarationObligations, *, work,
                          render: Callable[[Finding], BaseException],
                          fold: Callable[[str], str] | None = None,
                          facts: _NameFacts | None = None) -> int:
    """Whole paths precede charged prefix keys and adjacent-prefix comparisons.

    Admission is per original visit and counted prefix, even when component
    folds are reused. A substituted legacy fold hook observes each original
    call. Keys hold one string per declaration, never one trie node per prefix.
    """
    facts = facts or _NameFacts()
    fold = fold or facts.full_fold
    relatives = obligations.paths
    try:
        seen: dict[str, str] = {}
        for ordinal, relative in enumerate(relatives):
            key = fold(relative)
            if key in seen and seen[key] != relative:
                raise render(Finding("declared-alias", "declarations", (0, ordinal),
                                     path=relative, target=seen[key]))
            seen[key] = relative
        keys = []
        for relative in relatives:
            components = relative.split("/")
            work.charge(len(components))
            keys.append("\x00".join(fold(component) for component in components))
        nodes = 0
        previous_folded: list[str] = []
        previous_spelled: list[str] = []
        for ordinal, index in enumerate(sorted(range(len(relatives)), key=keys.__getitem__)):
            folded = keys[index].split("\x00")
            spelled = relatives[index].split("/")
            shared = 0
            limit = min(len(folded), len(previous_folded))
            while shared < limit and folded[shared] == previous_folded[shared]:
                shared += 1
            for depth in range(shared):
                if spelled[depth] != previous_spelled[depth]:
                    raise render(Finding("declared-prefix-alias", "declarations", (1, ordinal, depth),
                        path="/".join(spelled[:depth + 1]),
                        target="/".join(previous_spelled[:depth + 1])))
            work.charge(len(folded) - shared)
            nodes += len(folded) - shared
            if nodes > obligations.alias_index_limit:
                raise render(Finding("declared-index-budget", "declarations", (1, ordinal),
                                     target=str(obligations.alias_index_limit)))
            previous_folded, previous_spelled = folded, spelled
        return nodes
    except _names.NamePolicyError as exc:
        raise render(Finding("name", "declarations", (), detail=str(exc))) from exc


@dataclass(frozen=True)
class SubjectIdentity:
    """Session provenance, repository and immutable object identity."""

    session: object = field(repr=False)
    repository: str
    object_format: str
    commit: str
    tree: str


def _unsupported_attribute(path: str, line: int, construct: str) -> snapshot.SnapshotError:
    return snapshot.SnapshotError(
        f"unsupported .gitattributes construct at {path}:{line}: {construct}"
    )


def _attribute_pattern(
    token: bytes, *, path: str, line: int
) -> tuple[bytes, tuple[bytes, ...], bool]:
    try:
        shown = token.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise snapshot._unsupported_attribute(path, line, "non-ASCII pattern") from exc
    if not token:
        raise snapshot._unsupported_attribute(path, line, "empty pattern")
    if token.startswith(b'"'):
        raise snapshot._unsupported_attribute(path, line, "C-quoted pattern")
    if token.startswith(b"!"):
        raise snapshot._unsupported_attribute(path, line, "negative pattern")
    for byte, description in (
        (b"?", "?"),
        (b"[", "bracket expression"),
        (b"]", "bracket expression"),
        (b"\\", "backslash escape"),
    ):
        if byte in token:
            raise snapshot._unsupported_attribute(path, line, description)
    if token.endswith(b"/"):
        raise snapshot._unsupported_attribute(path, line, "trailing slash")
    if re.fullmatch(rb"[A-Za-z0-9._*/-]+", token) is None:
        raise snapshot._unsupported_attribute(path, line, f"pattern {shown!r}")
    anchored = token[1:] if token.startswith(b"/") else token
    if not anchored:
        raise snapshot._unsupported_attribute(path, line, "empty pattern")
    segments = anchored.split(b"/")
    if any(not segment for segment in segments):
        raise snapshot._unsupported_attribute(path, line, "empty pattern segment")
    for segment in segments:
        if b"**" in segment and segment != b"**":
            raise snapshot._unsupported_attribute(path, line, "misplaced **")
    if token == b"**":
        raise snapshot._unsupported_attribute(path, line, "misplaced **")
    return anchored, tuple(segments), token.startswith(b"/") or b"/" in anchored


def _parse_attribute_file(
    path: str, payload: bytes, *, rule_limit: int
) -> tuple[snapshot._AttributeRule, ...]:
    rules: list[snapshot._AttributeRule] = []
    rule_overflow = False
    line_number = 0
    position = 0
    while True:
        line_number += 1
        line_end = payload.find(b"\n", position)
        if line_end < 0:
            original = payload[position:]
        else:
            original = payload[position:line_end]
        # Git 2.53.0's read_attr_from_buf() stops reading the blob at an
        # embedded NUL, so every rule after one is unseen by git: refuse the
        # blob on any line rather than honour rules git never reads.
        if b"\0" in original:
            raise snapshot._unsupported_attribute(path, line_number, "control byte")
        # attr.c's parse_attr_line() skips leading blanks (space, tab and CR,
        # measured on git 2.53.0) and returns before any other test on an
        # empty line or a '#' comment, whatever the line's length or contents;
        # the reader skips those lines the same way (peer review, round 4).
        line = original.strip(b" \t\r")
        if line and not line.startswith(b"#"):
            # attr.h fixes ATTR_MAX_LINE_LENGTH at 2048 and parse_attr_line()
            # drops a rule line whose strlen(), leading blanks included, is at
            # least that; parse_attr() drops the whole rule when
            # attr_name_valid() or attr_name_reserved() rejects one state
            # name; and git splits fields at CR as well as at space and tab
            # (measured). Refuse these cases rather than disagreeing about
            # precedence.
            if len(original) >= 2048:
                raise snapshot._unsupported_attribute(
                    path, line_number, "line longer than 2048 bytes"
                )
            if any(byte < 0x20 and byte != 0x09 for byte in original):
                raise snapshot._unsupported_attribute(path, line_number, "control byte")
            fields = re.split(rb"[ \t]+", line)
            if len(fields) < 2:
                raise snapshot._unsupported_attribute(
                    path, line_number, "line has no attribute state"
                )
            if fields[0].startswith(b"[attr]"):
                raise snapshot._unsupported_attribute(
                    path, line_number, "attribute macro definition"
                )
            pattern, segments, has_slash = snapshot._attribute_pattern(
                fields[0], path=path, line=line_number
            )
            states: list[tuple[str, str]] = []

            def add_states(additions: tuple[tuple[str, str], ...]) -> None:
                if len(states) + len(additions) > snapshot.MAX_ATTRIBUTE_STATES_PER_LINE:
                    raise snapshot.SnapshotError(
                        f"attribute states at {path}:{line_number} exceed the "
                        f"per-line budget of {snapshot.MAX_ATTRIBUTE_STATES_PER_LINE} states"
                    )
                states.extend(additions)

            for raw_state in fields[1:]:
                try:
                    state = raw_state.decode("ascii", errors="strict")
                except UnicodeDecodeError as exc:
                    raise snapshot._unsupported_attribute(
                        path, line_number, "non-ASCII attribute state"
                    ) from exc
                if state == "binary":
                    add_states(
                        (
                            ("diff", "unset"),
                            ("merge", "unset"),
                            ("text", "unset"),
                        )
                    )
                    continue
                disposition = "set"
                name = state
                if state.startswith("-"):
                    disposition, name = "unset", state[1:]
                elif state.startswith("!"):
                    disposition, name = "unspecified", state[1:]
                elif "=" in state:
                    name, value = state.split("=", 1)
                    disposition = "value"
                if name.startswith(("-", "builtin_")) or re.fullmatch(
                    r"[A-Za-z0-9_.-]+", name
                ) is None:
                    raise snapshot._unsupported_attribute(
                        path, line_number, f"attribute name {name!r}"
                    )
                add_states(((name, disposition),))
            trailing_globstars = 0
            for segment in reversed(segments):
                if segment != b"**":
                    break
                trailing_globstars += 1
            trailing_descendants = bool(
                trailing_globstars and trailing_globstars < len(segments)
            )
            match_segments = (
                segments[:-trailing_globstars]
                if trailing_descendants
                else segments
            )
            rule = snapshot._AttributeRule(
                pattern,
                segments,
                match_segments,
                has_slash,
                trailing_descendants,
                tuple(states), source_line=line_number,
            )
            if len(rules) >= rule_limit:
                rule_overflow = True
            else:
                rules.append(rule)
        if line_end < 0:
            break
        position = line_end + 1
    if rule_overflow:
        raise snapshot.SnapshotError(
            f"attribute rules exceed the snapshot budget of "
            f"{snapshot.MAX_ATTRIBUTE_RULES_TOTAL} rules"
        )
    return tuple(rules)


def _segment_matches(
    pattern: bytes, value: bytes, step: Callable[[], None]
) -> bool:
    pattern_index = value_index = 0
    star = -1
    retry = 0
    while value_index < len(value):
        step()
        if (
            pattern_index < len(pattern)
            and pattern[pattern_index] != ord("*")
            and pattern[pattern_index] == value[value_index]
        ):
            pattern_index += 1
            value_index += 1
        elif pattern_index < len(pattern) and pattern[pattern_index] == ord("*"):
            star = pattern_index
            pattern_index += 1
            retry = value_index
        elif star >= 0:
            retry += 1
            value_index = retry
            pattern_index = star + 1
        else:
            return False
    while pattern_index < len(pattern) and pattern[pattern_index] == ord("*"):
        step()
        pattern_index += 1
    return pattern_index == len(pattern)


def _attribute_matches(
    rule: snapshot._AttributeRule, relative: tuple[bytes, ...], step: Callable[[], None]
) -> bool:
    if not rule.has_slash:
        return bool(relative) and snapshot._segment_matches(
            rule.segments[0], relative[-1], step
        )
    pattern_index = value_index = 0
    globstar = -1
    retry = 0
    while value_index < len(relative):
        if (
            rule.trailing_descendants
            and pattern_index == len(rule.match_segments)
        ):
            # The non-globstar prefix matched and at least one descendant
            # remains. Git's trailing ``/**`` excludes the directory itself.
            return True
        step()
        if (
            pattern_index < len(rule.match_segments)
            and rule.match_segments[pattern_index] == b"**"
        ):
            globstar = pattern_index
            pattern_index += 1
            retry = value_index
        elif (
            pattern_index < len(rule.match_segments)
            and snapshot._segment_matches(
                rule.match_segments[pattern_index],
                relative[value_index],
                step,
            )
        ):
            pattern_index += 1
            value_index += 1
        elif globstar >= 0:
            retry += 1
            value_index = retry
            pattern_index = globstar + 1
        else:
            return False
    while (
        pattern_index < len(rule.match_segments)
        and rule.match_segments[pattern_index] == b"**"
    ):
        step()
        pattern_index += 1
    if rule.trailing_descendants:
        return False
    return pattern_index == len(rule.match_segments)


def load_attribute_rules(
    self, parts: tuple[bytes, ...]
) -> tuple[snapshot._AttributeRule, ...]:
    path_bytes = b"/".join(parts)
    path = snapshot._tree_path_decode(path_bytes)
    cached = self._state.attribute_cache.get(path)
    if cached is not None:
        return cached
    raw = self._raw_entry_at(parts)
    if raw is None:
        self._state.attribute_cache[path] = ()
        return ()
    if raw.mode not in {b"100644", b"100755"}:
        raise snapshot.SnapshotError(
            f"unsupported .gitattributes entry at {path}: mode {raw.display_mode}"
        )
    _kind, size = self._batch().info(raw.oid, role="blob")
    if self._verification_total("attribute_bytes") + size > snapshot.MAX_ATTRIBUTE_BYTES_TOTAL:
        raise snapshot.SnapshotError(
            f"attribute bytes exceed the snapshot budget of "
            f"{snapshot.MAX_ATTRIBUTE_BYTES_TOTAL} bytes"
        )
    entry = self._public_entry(parts, raw)
    payload = self.blob(entry, limit=snapshot.MAX_ATTRIBUTE_BYTES)
    self._charge_verification(
        "attribute_bytes",
        size,
        ceiling=snapshot.MAX_ATTRIBUTE_BYTES_TOTAL,
        message=f"attribute bytes exceed the snapshot budget of {snapshot.MAX_ATTRIBUTE_BYTES_TOTAL} bytes",
    )
    remaining_rules = (
        snapshot.MAX_ATTRIBUTE_RULES_TOTAL
        - self._verification_total("attribute_rules")
    )
    rules = snapshot._parse_attribute_file(
        path, payload, rule_limit=max(0, remaining_rules)
    )
    if self._verification_total("attribute_rules") + len(rules) > snapshot.MAX_ATTRIBUTE_RULES_TOTAL:
        raise snapshot.SnapshotError(
            f"attribute rules exceed the snapshot budget of "
            f"{snapshot.MAX_ATTRIBUTE_RULES_TOTAL} rules"
        )
    self._charge_verification(
        "attribute_rules",
        len(rules),
        ceiling=snapshot.MAX_ATTRIBUTE_RULES_TOTAL,
        message=f"attribute rules exceed the snapshot budget of {snapshot.MAX_ATTRIBUTE_RULES_TOTAL} rules",
    )
    self._state.attribute_cache[path] = rules
    return rules



@dataclass(frozen=True)
class AttributeState:
    """One final disposition and its committed source, independently per reading."""

    disposition: str
    source: str
    line: int


@dataclass(frozen=True)
class AttributeOutcome:
    """Completed exact and ASCII-folded readings for one admitted raw path."""

    exact: Mapping[str, AttributeState]
    folded: Mapping[str, AttributeState]
    sources: tuple[str, ...]

    def finding(self, path: bytes, ordinal: int) -> Finding | None:
        for name in ("filter", "ident", "working-tree-encoding"):
            for reading, states in (("exact", self.exact), ("folded", self.folded)):
                state = states.get(name)
                if state is not None and state.disposition in {"set", "value"}:
                    return Finding("transforming-attribute", "attributes", (ordinal,),
                                   path=snapshot._tree_path_decode(path), raw_path=path,
                                   name=name, operation=reading, source=state.source,
                                   line=state.line)
        return None


@dataclass(frozen=True)
class _RuleCheckpoint:
    # One checkpoint per rule/reading, never one object per matching step.
    cost: int
    matched: bool


@dataclass(frozen=True)
class AttributeWork:
    rule_evaluations: int
    exhaustion_replays: int
    matching_steps: int
    applied_states: int
    checkpoint_entries: int
    path_outcomes: int
    plan_outcomes: int
    folded_rules: int
    folded_paths: int


def _fold_attribute_path(parts: tuple[bytes, ...]) -> tuple[bytes, ...]:
    return tuple(segment.lower() for segment in parts)


class _AttributeStore:
    """Verification-local facts; acceptance keys also bind subject and full plan.

    Linked candidate/base readers still load and admit their own committed
    sources. Only pure rule/relative-path facts can be shared after those reads;
    an OID never authorizes an outcome in another subject or scope.
    """

    def __init__(self):
        self.checkpoints: dict[tuple, _RuleCheckpoint] = {}
        self.folds: dict[tuple, snapshot._AttributeRule] = {}
        self.folded_paths: dict[tuple, tuple[bytes, ...]] = {}
        self.paths: dict[tuple, AttributeOutcome] = {}
        self.plans: dict[tuple, AttributeOutcome] = {}
        self.attempted: set[tuple] = set()
        self.rule_evaluations = self.exhaustion_replays = 0
        self.matching_steps = self.applied_states = 0

    def merge(self, other: _AttributeStore) -> None:
        for name in ("checkpoints", "folds", "folded_paths", "paths", "plans"):
            getattr(self, name).update(getattr(other, name))
        self.attempted.update(other.attempted)
        for name in ("rule_evaluations", "exhaustion_replays", "matching_steps", "applied_states"):
            setattr(self, name, getattr(self, name) + getattr(other, name))

    @property
    def work(self) -> AttributeWork:
        return AttributeWork(self.rule_evaluations, self.exhaustion_replays,
                             self.matching_steps, self.applied_states,
                             len(self.checkpoints), len(self.paths), len(self.plans), len(self.folds),
                             len(self.folded_paths))

    def folded_path(self, version: str, parts: tuple[bytes, ...]) -> tuple[bytes, ...]:
        key = version, parts
        result = self.folded_paths.get(key)
        if result is None:
            result = _fold_attribute_path(parts)
            self.folded_paths[key] = result
        return result

    def rule(self, subject: snapshot.TreeSnapshot, version: str, fold: bool,
             rule: snapshot._AttributeRule, relative: tuple[bytes, ...]) -> _RuleCheckpoint:
        # Resolve legacy hooks after import. Including the matcher hooks in the
        # fact key also observes a replacement made after a completed request.
        key = (version, fold, rule, relative, snapshot._attribute_matches,
               snapshot._segment_matches, type(subject)._attribute_step)
        checkpoint = self.checkpoints.get(key)
        if checkpoint is not None:
            remaining = (snapshot.MAX_ATTRIBUTE_MATCH_WORK
                         - subject._verification_total("attribute_match_work"))
            if checkpoint.cost <= remaining or not checkpoint.cost:
                if checkpoint.cost:
                    _charge_attribute_work(subject, checkpoint.cost)
                return checkpoint
        # A partial first attempt has no completed checkpoint. A resumed call
        # can revisit that one unfinished rule; earlier successes are arithmetic.
        if key in self.attempted:
            self.exhaustion_replays += 1
        else:
            self.rule_evaluations += 1
        start = subject.work.attribute_match_work

        def step():
            subject._attribute_step()
            self.matching_steps += 1

        try:
            matched = snapshot._attribute_matches(rule, relative, step)
            if matched:
                for _ in rule.states:
                    subject._attribute_step()
                    self.applied_states += 1
        finally:
            # Hash the potentially large rule key once per attempt, including
            # partial exhaustion, rather than once per matching/applied step.
            if subject.work.attribute_match_work > start:
                self.attempted.add(key)
        checkpoint = _RuleCheckpoint(subject.work.attribute_match_work - start, matched)
        self.checkpoints[key] = checkpoint
        return checkpoint


def _attribute_store(subject: snapshot.TreeSnapshot) -> _AttributeStore:
    pool = subject._state.work_pool.root()
    if pool.attributes is None:
        pool.attributes = _AttributeStore()
    return pool.attributes


def _charge_attribute_work(subject: snapshot.TreeSnapshot, amount: int = 1) -> None:
    subject._charge_verification(
        "attribute_match_work", amount, ceiling=snapshot.MAX_ATTRIBUTE_MATCH_WORK,
        message=f"attribute matching exceeds the work budget of {snapshot.MAX_ATTRIBUTE_MATCH_WORK} steps",
    )


def _admit_attribute_paths(subject: snapshot.TreeSnapshot, paths: Iterable) -> tuple[tuple[str, ...], dict[bytes, tuple[bytes, ...]]]:
    ordered = []
    unique = {}
    for count, supplied in enumerate(paths, start=1):
        if count > snapshot.MAX_TREE_ENTRIES:
            raise snapshot.SnapshotError(
                f"attribute paths exceed the budget of {snapshot.MAX_TREE_ENTRIES} entries")
        value = supplied.path if isinstance(supplied, snapshot.GitEntry) else supplied
        parts = subject._path_parts(value, allow_empty=False)
        raw = b"/".join(parts)
        subject._charge_path_bytes(raw)
        ordered.append(snapshot._tree_path_decode(raw))
        unique.setdefault(raw, parts)
    return tuple(ordered), unique


def attribute_error(finding: Finding) -> snapshot.SnapshotError:
    """The retained snapshot refusal renderer, also used at verifier barriers."""
    if finding.kind != "transforming-attribute" or finding.raw_path is None:
        raise PolicyUseError("not an attribute finding")
    try:
        path = finding.raw_path.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return snapshot.SnapshotError("tree entry name is not valid UTF-8 for quoting")
    return snapshot.SnapshotError(
        f"transforming attribute {finding.name} applies to protected path {path}")


def refuse_attributes(subject: snapshot.TreeSnapshot, paths: Iterable) -> None:
    """Forward already checked collection arguments without pre-consuming them."""
    ordered, unique = _admit_attribute_paths(subject, paths)
    plan = ProtectionPlan(attribute_target_selectors=ordered, listing_scope=(),
                          obligations=("attributes",), use="snapshot-attributes", phase="attributes")
    evaluator = TreePolicy(subject, policy_version=POLICY_VERSION, work=subject.work)
    view = evaluator.evaluate_attributes(plan, _admitted=unique)
    view.require(plan.use, render=attribute_error)


@dataclass(frozen=True)
class TreePolicy:
    """Verification-local evaluator over an entered authenticated TreeSnapshot.

    The fixed version describes v0.6 exact-plus-ASCII-fold attribute semantics.
    Reader limits/hooks are consulted at call time. Private caches share the
    snapshot's existing candidate/base ledger, never acceptance across subjects.
    """

    snapshot: snapshot.TreeSnapshot
    policy_version: str = field(kw_only=True)
    work: snapshot.SnapshotWork = field(kw_only=True)
    _facts: _NameFacts = field(default_factory=_NameFacts, init=False, repr=False, compare=False)
    _shapes: _ShapeFacts = field(default_factory=_ShapeFacts, init=False, repr=False, compare=False)
    _entries: dict[str, snapshot.GitEntry] = field(default_factory=dict, init=False, repr=False, compare=False)
    _scopes: dict[str, str | None] = field(default_factory=dict, init=False, repr=False, compare=False)
    _empty_roots: dict[str, bool] = field(default_factory=dict, init=False, repr=False, compare=False)
    _runs: dict[ProtectionPlan, _NameRun] = field(default_factory=dict, init=False, repr=False, compare=False)
    _export_counts: dict[str, int] = field(default_factory=lambda: dict(prefixes=0, leaves=0, components=0, directory_records=0), init=False, repr=False, compare=False)
    _views: WeakValueDictionary = field(default_factory=WeakValueDictionary, init=False, repr=False, compare=False)
    _selections: WeakValueDictionary = field(default_factory=WeakValueDictionary, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self.snapshot) is not snapshot.TreeSnapshot or self.work is not self.snapshot.work:
            raise PolicyUseError("policy subject/work mismatch")
        if self.policy_version != POLICY_VERSION:
            raise PolicyUseError("unsupported protected-tree policy version")
        self.snapshot._batch()

    @property
    def subject(self) -> SubjectIdentity:
        return SubjectIdentity(self.snapshot._state.entry_token, str(self.snapshot.git_dir),
                               self.snapshot.object_format, self.snapshot.commit, self.snapshot.tree)

    @property
    def name_work(self) -> NameWork:
        return self._facts.work

    @property
    def shape_work(self) -> ShapeWork:
        return self._shapes.work

    @property
    def attribute_work(self) -> AttributeWork:
        return _attribute_store(self.snapshot).work

    @property
    def export_work(self) -> ExportWork:
        return ExportWork(**self._export_counts)

    def _read_export(self, plan: ProtectionPlan) -> _NameRun:
        """Acquire exactly the old export reads, retaining uncharged raw topology.

        Immediate ancestor records prove spellings/declared modes only: their
        off-scope object types have not been probed. Selected TreeListing nodes
        additionally authenticate tree objects, including empty trees. Neither
        kind of directory observation creates a payload-capable GitEntry.
        """
        selected: dict[str, snapshot.GitEntry] = {}
        run = _NameRun(MappingProxyType(selected), plan, self._facts, self._shapes)

        def remember(parts, records, oid):
            path = snapshot._tree_path_decode(b"/".join(parts))
            if path not in run.raw_listings:
                run.raw_listings[path] = records
                run.tree_ids[path] = oid
                self._export_counts["directory_records"] += len(records)

        def topology(parts, node):
            remember(parts, tuple(r.raw for r in node.records), node.tree_oid)
            path = snapshot._tree_path_decode(b"/".join(parts))
            run.mode_facts[path, "ancestor"] = self._shapes.metadata(
                path, "040000", "tree", empty=not node.records)
            for record in node.records:
                if record.child is not None:
                    topology((*parts, record.raw.name), record.child)

        def add(entry):
            selected[entry.path] = entry
            self._export_counts["leaves"] += 1
            if len(selected) > snapshot.MAX_TREE_ENTRIES:
                raise snapshot.SnapshotError(
                    f"tree walk exceeds the budget of {snapshot.MAX_TREE_ENTRIES} entries")

        for parts in export_prefixes(self.snapshot, plan.export_requests):
            self._export_counts["prefixes"] += 1
            raw = self.snapshot._raw_entry_at(parts) if parts else None
            if parts:
                # The exact lookup just authenticated these tree records. Reuse
                # them without another reader call, path charge or object probe.
                oid = self.snapshot.tree
                for depth, component in enumerate(parts):
                    records = self.snapshot._state.tree_cache[oid]
                    remember(parts[:depth], records, oid)
                    reached = self.snapshot._find_raw_entry(records, component)
                    if reached is None or reached.mode != b"40000":
                        break
                    oid = reached.oid
                if raw is None:
                    continue
            if not parts or raw.mode == b"40000":
                listing = self.snapshot.entries(b"/".join(parts) if parts else "")
                for entry in listing:
                    add(entry)
                topology(parts, listing._node)
            else:
                add(self.snapshot._public_entry(parts, raw))
        # Successful exact lookups discharge ancestors at the reader's existing
        # barrier, with its missing-prefix and wrong-shape behavior unchanged.
        run.children = index_children(selected)
        run.completed.add("ancestors")
        return run

    def _export_names(self, run: _NameRun) -> None:
        for ordinal, (parent, names) in enumerate(run.export_siblings.items()):
            path = snapshot._tree_path_decode(b"/".join(parent))
            try:
                self._facts.siblings(sorted(names), repertoire=run.plan.repertoire,
                                     materializing=True, label=path or "tree root")
            except _names.NamePolicyError as exc:
                run.findings.append(Finding(
                    "sibling-alias" if isinstance(exc, _SiblingCollision) else "name",
                    "export-names", (ordinal, getattr(exc, "ordinal", 0)),
                    parent=path, name=getattr(exc, "name", ""),
                    other_name=getattr(exc, "other", ""), operation="export-siblings",
                    detail=str(exc)))
                return
        run.completed.add("export-names")

    def regular_entries(self, entries: Mapping[str, snapshot.GitEntry],
                        paths: Iterable[str]) -> tuple[snapshot.GitEntry, ...]:
        """Classify a caller's ordered attribute targets without payload authority."""
        return regular_entries(entries, paths, facts=self._shapes)

    def manifest_children(self, prefix: str) -> Mapping[str, ModeFact]:
        """Admit immediate children at append's proposal barrier, including trees."""
        children = self.snapshot.entries(prefix).children
        return MappingProxyType({name: (
            self._shapes.mode(child.path, child) if isinstance(child, snapshot.GitEntry)
            else self._shapes.metadata(prefix + "/" + name, "040000", "tree")
        ) for name, child in children.items()})

    def manifest_initialized(self, prefix: str) -> bool:
        """Retain non-tree iteration and path charges in append's push probe."""
        return bool(self.snapshot.entries(prefix))

    def materialize(self, plan: ProtectionPlan, destination) -> snapshot.Materialization:
        """Admit a conditional export, then certify it at the writer's old barrier.

        Each explicit materialization repeats reader admission; its name and
        shape facts share this evaluator. Physical writes and guards stay in
        the snapshot writer. Attributes are a separate earlier append barrier.
        """
        admitted = self.snapshot.materialize(plan.export_prefixes, destination,
                                              repertoire=plan.repertoire)
        export = replace(plan, obligations=EXPORT_STAGES, listing_scope=(),
                         use="materialize", phase="export", ancestor_paths=(), mode_roles=(),
                         export_requests=admitted._prefixes)
        return _PolicyMaterialization(self, admitted, export)

    def observe_entries(self, entries: Iterable[snapshot.GitEntry]) -> None:
        """Retain entries already admitted at a legacy read, with no new walk."""
        self.snapshot._batch()
        for entry in entries:
            self.snapshot._require_entry(entry)
            self._entries[entry.path] = entry

    def read_listing(self, prefix: str = "") -> dict[str, snapshot.GitEntry]:
        """Admit a legacy listing use, including repeated path/walk charges.

        Policy stage reuse never calls this again for an already acquired scope.
        An explicit caller read still invokes the reader and honors all existing
        counters and late limits before deduplicating immutable metadata.
        """
        self.snapshot._batch()
        listing = self.snapshot.entries(prefix)
        entries = listing.as_dict(include_trees=True)
        self._entries.update(entries)
        self._scopes[prefix] = listing.tree_oid
        self._empty_roots[prefix] = not listing._node.records
        return entries

    def _validate_view(self, view: ProtectedTreeView) -> None:
        self.snapshot._batch()
        if (type(view) is not ProtectedTreeView or view._evaluator is not self
                or self._views.get(id(view)) is not view or view.subject != self.subject
                or view.policy_version != self.policy_version):
            raise PolicyUseError("protected view does not belong to this evaluator/subject")

    def evaluate(self, plan: ProtectionPlan, *, stage: str,
                 previous: ProtectedTreeView | None = None) -> ProtectedTreeView:
        """Evaluate newly required obligations at the caller's existing barrier.

        Stages: names and aliases, modes and ancestors, export names,
        binding content roots and suffix-selected leaves, and attributes. Earlier completed facts are reused. Repeated explicit
        listing reads retain reader admission charges; evaluating a completed
        name, shape or export fact adds none. Attributes are the exception: a
        repeated attribute plan replays its admission under the record's D12
        compatibility charge schedule (input counts and path bytes charged
        before deduplication, checkpoint blocks replayed arithmetically, a
        single exhausting rule re-executed from its checkpoint), so the public
        counters land where the legacy path left them. Previous evidence must
        be issued by this evaluator for this exact plan, including anchor origin
        and later obligations. No later-stage I/O occurs.
        """
        self.snapshot._batch()
        if previous is not None:
            self._validate_view(previous)
            if previous.plan != plan:
                raise PolicyUseError("protected view has an incompatible plan")
        if stage not in (*NAME_STAGES, *SHAPE_STAGES, *BINDING_STAGES, "export-names", "attributes"):
            raise NotImplementedError(f"protected-tree stage {stage!r} belongs to a later migration")
        exporting = "export-names" in plan.obligations
        if exporting and (
            plan.obligations != EXPORT_STAGES or plan.listing_scope
            or tuple(snapshot._tree_path_decode(p) if type(p) is bytes else p
                     for p in plan.export_requests) != plan.export_prefixes
        ):
            raise PolicyUseError("export plan has incompatible obligations/listing scope")
        for scope in plan.listing_scope:
            if scope not in self._scopes:
                self.read_listing(scope)
        run = self._runs.get(plan)
        if run is None and exporting:
            run = self._read_export(plan)
            self._runs[plan] = run
        if run is None:
            # The run owns a stable copy; unrelated later listing extensions do
            # not silently widen its obligations or mutate an already issued view.
            exact = {path for path, _ in plan.mode_roles}
            ancestors = {"/".join(path.split("/")[:depth]) for path in plan.ancestor_paths
                         for depth in range(1, len(path.split("/")))}
            # Exact mode uses (notably each base-history comparison) must not
            # rescan the entire admitted release listing for every leaf.
            selected = {path: entry for path, entry in self._entries.items() if any(
                not scope or path == scope or path.startswith(scope + "/")
                for scope in plan.listing_scope
            )} if plan.listing_scope else {}
            selected.update((path, self._entries[path]) for path in exact | ancestors
                            if path in self._entries)
            run = _NameRun(MappingProxyType(selected), plan, self._facts, self._shapes)
            self._runs[plan] = run
        # The plan is the schedule: callers may stop after names, admit one
        # state lookup/payload, then request a separate shape obligation.
        stages = plan.obligations[:plan.obligations.index(stage) + 1] if stage in plan.obligations else (stage,)
        for current in stages:
            if current == "attributes":
                if not any(f.stage != "attributes" for f in run.findings):
                    self.evaluate_attributes(plan, _run=run)
                continue
            if current in run.completed or run.findings:
                continue
            if current in NAME_STAGES:
                run.evaluate(current)
            elif current == "modes":
                self.evaluate_modes(plan, _run=run)
            elif current == "ancestors":
                self.evaluate_ancestors(plan, _run=run)
            elif current == "export-names":
                self._export_names(run)
            elif current in BINDING_STAGES:
                run.binding(current)
            else:
                raise NotImplementedError(f"protected-tree stage {current!r} belongs to a later migration")
        return self._view(plan, run)

    def _view(self, plan: ProtectionPlan, run: _NameRun) -> ProtectedTreeView:
        entries = MappingProxyType(dict(run.entries))
        children = {p: {} for p in plan.listing_scope} | run.children
        view = ProtectedTreeView(
            subject=self.subject, plan=plan, policy_version=self.policy_version,
            entries=entries,
            raw_paths=tuple(p.encode("utf-8", "surrogateescape") for p in entries),
            names=tuple(entries),
            listings=MappingProxyType({p: MappingProxyType(dict(v)) for p, v in children.items()}),
            listing_scopes=plan.listing_scope,
            listing_tree_ids=MappingProxyType({p: self._scopes[p] for p in plan.listing_scope}),
            fold_index=MappingProxyType({p: f for p, f in self._facts.folds.items() if isinstance(f, str)}),
            mode_facts=MappingProxyType(dict(run.mode_facts)),
            attribute_outcomes=MappingProxyType(dict(run.attribute_outcomes)),
            findings=tuple(run.findings), completed=frozenset(run.completed),
            refused=frozenset(f.stage for f in run.findings),
            unevaluated=frozenset(plan.obligations) - run.completed - {f.stage for f in run.findings},
            admission=tuple((f.name, getattr(self.work, f.name)) for f in fields(self.work)),
            _evaluator=self, selected_paths=run.selected_paths,
            raw_listings=MappingProxyType(dict(run.raw_listings)),
            raw_listing_tree_ids=MappingProxyType(dict(run.tree_ids)),
        )
        self._views[id(view)] = view
        return view

    def evaluate_modes(self, plan: ProtectionPlan | None = None, *,
                       previous: ProtectedTreeView | None = None,
                       _run: _NameRun | None = None) -> ProtectedTreeView | None:
        """Classify the plan's ordered roles using only admitted metadata."""
        if plan is None:
            # PR2 pinned the unsupported no-plan call in its unchanged suite.
            raise NotImplementedError("receipt 0.7 M1 PR3 mode evaluation requires a plan")
        if _run is None:
            return self.evaluate(plan, stage="modes", previous=previous)
        self.snapshot._batch()
        if self._runs.get(plan) is not _run:
            raise PolicyUseError("mode run does not belong to this evaluator/plan")
        parents = {path.rpartition("/")[0] for path in _run.entries}
        exporting = "export-names" in plan.obligations
        roles = tuple((path, "export-leaf") for path in sorted(_run.entries)) if exporting else plan.mode_roles
        for ordinal, (path, role) in enumerate(roles):
            entry = _run.entries.get(path)
            # Only complete listings establish tree emptiness; exact entries
            # alone establish directory shape, without an extra subtree read.
            complete = any(not p or path == p or path.startswith(p + "/") for p in plan.listing_scope)
            if entry is None and self._scopes.get(path) is not None:
                # A subtree listing carries its root OID separately, including
                # empty roots. Do not manufacture/charge a public GitEntry or
                # confuse that authenticated directory with an absent leaf.
                fact = self._shapes.metadata(path, "040000", "tree", empty=self._empty_roots[path])
            else:
                fact = self._shapes.mode(path, entry, empty=complete and path not in parents
                                         and entry is not None and entry.mode == "040000")
            _run.mode_facts[path, role] = fact
            finding = fact.finding(path, role, position=(ordinal,))
            if finding is not None:
                _run.findings.append(finding)
                return None
            if exporting:
                raw_parts = self.snapshot._path_parts(path, allow_empty=False)
                self._export_counts["components"] += len(raw_parts)
                for index, name in enumerate(raw_parts):
                    _run.export_siblings.setdefault(raw_parts[:index], set()).add(name)
        _run.completed.add("modes")
        return None

    def evaluate_ancestors(self, plan: ProtectionPlan | None = None, *,
                           previous: ProtectedTreeView | None = None,
                           _run: _NameRun | None = None) -> ProtectedTreeView | None:
        """Find the first wrong component without reading beyond this barrier."""
        if plan is None:
            raise NotImplementedError("receipt 0.7 M1 PR3 ancestor evaluation requires a plan")
        if _run is None:
            return self.evaluate(plan, stage="ancestors", previous=previous)
        self.snapshot._batch()
        if self._runs.get(plan) is not _run:
            raise PolicyUseError("ancestor run does not belong to this evaluator/plan")
        for ordinal, path in enumerate(plan.ancestor_paths):
            # A leaf-only view cannot prove absent ancestors or tree emptiness.
            if "" not in self._scopes:
                raise PolicyUseError("ancestor evaluation requires a complete ancestor listing")
            finding = self._shapes.ancestor(path, _run.entries)
            if finding is not None and (finding.kind != "missing" or plan.require_ancestors):
                _run.findings.append(replace(finding, position=(ordinal, *finding.position)))
                return None
        _run.completed.add("ancestors")
        return None

    def select_export(self, view: ProtectedTreeView | None = None, *,
                      render: Callable[[Finding], BaseException] | None = None) -> ProtectedSelection:
        """Certify regular exports from this subject's completed export view."""
        if view is None:
            # PR2 pins the unsupported no-view call, like the no-plan shape APIs.
            raise NotImplementedError("receipt 0.7 M1 PR3 export selection requires a view")
        self._validate_view(view)
        if render is None:
            raise PolicyUseError("export selection requires a compatibility renderer")
        if view.plan.obligations != EXPORT_STAGES:
            raise PolicyUseError("protected view lacks export obligations")
        return view.require(view.plan.use, render=render)

    def evaluate_attributes(self, plan: ProtectionPlan | None = None, *,
                            previous: ProtectedTreeView | None = None,
                            _run: _NameRun | None = None,
                            _admitted: dict[bytes, tuple[bytes, ...]] | None = None) -> ProtectedTreeView | None:
        """Evaluate committed sources at this barrier, replaying D12 admission.

        Completed path outcomes are subject/version bound; acceptance additionally
        binds the complete plan fingerprint. Repeated and overlapping requests
        replay each source read and rule checkpoint in the old exact/fold order.
        Only an exhausting rule reexecutes matching and applied-state steps.
        """
        if plan is None:
            # PR2 freezes the no-plan call, as it does for modes and ancestors.
            raise NotImplementedError("receipt 0.7 M1 PR4 attribute evaluation requires a plan")
        self.snapshot._batch()
        if _run is None:
            if _admitted is None:
                return self.evaluate(plan, stage="attributes", previous=previous)
            # Only the collection facade has already charged the ordered input.
            if plan.obligations != ("attributes",) or plan.listing_scope:
                raise PolicyUseError("attribute facade has incompatible obligations")
            run = _NameRun(MappingProxyType({}), plan, self._facts)
            self.evaluate_attributes(plan, _run=run, _admitted=_admitted)
            return self._view(plan, run)
        run = _run
        if _admitted is None:
            _, _admitted = _admit_attribute_paths(self.snapshot, plan.attribute_target_selectors)
        run.completed.discard("attributes")
        run.findings[:] = [f for f in run.findings if f.stage != "attributes"]
        run.attribute_outcomes.clear()
        store = _attribute_store(self.snapshot)
        fingerprint = plan.fingerprint
        for ordinal, (raw, parts) in enumerate(_admitted.items()):
            path_key = (self.subject, self.policy_version, raw,
                        snapshot._attribute_matches, snapshot._segment_matches,
                        type(self.snapshot)._attribute_step, type(self.snapshot)._attribute_rules)
            plan_key = (*path_key, fingerprint)
            cached = store.plans.get(plan_key) or store.paths.get(path_key)
            readings = []
            sources = []
            for fold in (False, True):
                final = {}
                for depth in range(len(parts)):
                    attribute_parts = (*parts[:depth], b".gitattributes")
                    # Keep this hook even on outcome reuse: the source loader
                    # owns its snapshot-local cache, authentication and charges.
                    rules = self.snapshot._attribute_rules(attribute_parts)
                    source = snapshot._tree_path_decode(b"/".join(attribute_parts))
                    if not fold:
                        sources.append(source)
                    relative = parts[depth:]
                    if fold:
                        relative = store.folded_path(self.policy_version, parts)[depth:]
                    for rule in rules:
                        source_line = rule.source_line
                        if fold:
                            fold_key = (self.policy_version, rule)
                            folded = store.folds.get(fold_key)
                            if folded is None:
                                folded = replace(rule, pattern=rule.pattern.lower(),
                                                 segments=tuple(s.lower() for s in rule.segments),
                                                 match_segments=tuple(s.lower() for s in rule.match_segments))
                                store.folds[fold_key] = folded
                            rule = folded
                        checkpoint = store.rule(self.snapshot, self.policy_version, fold, rule, relative)
                        if cached is None and checkpoint.matched:
                            for name, disposition in rule.states:
                                final[name] = AttributeState(disposition, source, source_line)
                readings.append(MappingProxyType(final))
            result = cached or AttributeOutcome(readings[0], readings[1], tuple(sources))
            store.paths[path_key] = store.plans[plan_key] = result
            run.attribute_outcomes[raw] = result
            finding = result.finding(raw, ordinal)
            if finding is not None:
                run.findings.append(finding)
                return None
        run.completed.add("attributes")
        return None

@dataclass(frozen=True)
class ProtectedTreeView:
    """Frozen authenticated metadata, partial topology and name completion.

    Index backing storage is privately copied. None from finding_for does not
    accept unevaluated obligations. No blob payloads or attribute outcomes are
    fabricated here; later-stage obligations remain explicitly unevaluated.
    """

    subject: SubjectIdentity
    plan: ProtectionPlan
    policy_version: str
    entries: Mapping[str, snapshot.GitEntry]
    raw_paths: tuple[bytes, ...]
    names: tuple[str, ...]
    listings: Mapping[str, Mapping[str, snapshot.GitEntry]]
    listing_scopes: tuple[str, ...]
    listing_tree_ids: Mapping[str, str | None]
    fold_index: Mapping[str, str]
    findings: tuple[Finding, ...]
    completed: frozenset[str]
    refused: frozenset[str]
    unevaluated: frozenset[str]
    admission: tuple[tuple[str, int], ...]
    _evaluator: TreePolicy = field(repr=False, compare=False)
    mode_facts: Mapping[tuple[str, str], ModeFact] = field(
        default_factory=lambda: MappingProxyType({}), kw_only=True)

    attribute_outcomes: Mapping[bytes, AttributeOutcome] = field(
        default_factory=lambda: MappingProxyType({}), kw_only=True)

    # Raw directory records preserve selected empty trees and actual ancestor
    # spellings without manufacturing or charging public tree entries.
    raw_listings: Mapping[str, tuple[snapshot._RawTreeEntry, ...]] = field(
        default_factory=lambda: MappingProxyType({}), kw_only=True)
    raw_listing_tree_ids: Mapping[str, str | None] = field(
        default_factory=lambda: MappingProxyType({}), kw_only=True)

    selected_paths: tuple[str, ...] | None = field(default=None, kw_only=True)

    @property
    def plan_fingerprint(self) -> str:
        return self.plan.fingerprint

    def finding_for(self, use: str) -> Finding | None:
        """Select by stage, traversal ordinal and within-entry sub-step.

        In append, each entry's whole fold precedes that entry's target/depth
        comparisons; an earlier entry's alias still beats a later fold failure.
        """
        self._evaluator._validate_view(self)
        if use != self.plan.use:
            raise PolicyUseError("protected view has a different purpose")
        return min(self.findings, key=lambda f: (self.plan.obligations.index(f.stage), f.position), default=None)

    def require(self, use: str, *, render: Callable[[Finding], BaseException]) -> ProtectedSelection:
        """Render a refusal or issue a selection bound to completed obligations.

        Renderers choose public words/classes only. An incomplete or forged view
        refuses internally, even when finding_for returned None.
        """
        finding = self.finding_for(use)
        if finding is not None:
            refusal = render(finding)
            if not isinstance(refusal, BaseException):
                raise PolicyUseError("finding renderer must refuse")
            raise refusal
        if self.unevaluated or not set(self.plan.obligations) <= self.completed:
            raise PolicyUseError("protected obligations are unevaluated")
        entries = self.entries if self.selected_paths is None else MappingProxyType(
            {path: self.entries[path] for path in self.selected_paths})
        selection = ProtectedSelection(self.subject, use, self.plan_fingerprint,
                                       self.policy_version, entries, self.completed, self._evaluator)
        self._evaluator._selections[id(selection)] = selection
        return selection


@dataclass(frozen=True)
class ProtectedSelection:
    """Successful metadata selection bound to session, purpose and completed work.

    Only the recorded obligations are certified. Export selections require all
    export stages; attribute obligations remain a separate later barrier.
    Closing/abandoning a snapshot invalidates subsequent selection consumption.
    """

    subject: SubjectIdentity
    purpose: str
    plan_fingerprint: str
    policy_version: str
    entries: Mapping[str, snapshot.GitEntry]
    completed: frozenset[str]
    _evaluator: TreePolicy = field(repr=False, compare=False)

    def entries_for(self, subject: snapshot.TreeSnapshot, *, use: str,
                    plan: ProtectionPlan | None = None) -> Mapping[str, snapshot.GitEntry]:
        subject._batch()
        if (subject is not self._evaluator.snapshot or use != self.purpose
                or self._evaluator._selections.get(id(self)) is not self):
            raise PolicyUseError("protected selection subject/purpose mismatch")
        if plan is not None and (plan.fingerprint != self.plan_fingerprint or plan.use != use):
            raise PolicyUseError("protected selection has an incompatible plan")
        return self.entries


@dataclass(frozen=True)
class DirectoryEvidence:
    """Distinct bounded direct-reader observations, with no Git/whole-tree claim.

    PR3 adapts regular-file and ancestor facts. Existing lstat, spelling,
    open/fstat, race guards and read-once behavior stay with the directory reader.
    Observations cannot be supplied as a TreePolicy subject or prior view.
    """

    origin: str = "directory"
    observations: tuple[tuple[str, str], ...] = ()
    provenance: object = field(default_factory=object, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "observations", tuple(tuple(item) for item in self.observations))


class _PolicyMaterialization(snapshot.Materialization):
    """Use an existing evaluator while retaining the snapshot's physical writer."""

    def __init__(self, policy: TreePolicy, admitted: snapshot.Materialization,
                 plan: ProtectionPlan):
        super().__init__(policy.snapshot, admitted._prefixes,
                         admitted._destination, admitted._repertoire)
        self._policy = policy
        self._export_plan = plan

    def _selected_entries(self) -> dict[str, snapshot.GitEntry]:
        # An explicit new writer use admits its reads again, even if an earlier
        # materialization used this same plan. Stage-only reuse still adds none.
        self._policy._runs[self._export_plan] = self._policy._read_export(self._export_plan)
        view = self._policy.evaluate(self._export_plan, stage="export-names")
        selection = self._policy.select_export(view, render=self._export_error)
        return dict(selection.entries_for(self._snapshot, use=self._export_plan.use,
                                           plan=self._export_plan))
'''
# END verbatim src/receipt/protected_tree.py

# BEGIN verbatim 9dc1f85fc0e06cb58b73bad6d09da4c89ee9a4d6:src/receipt/verify.py
FROZEN_SOURCE['src/receipt/verify.py'] = r'''"""The spanning verification pass: custody, then binding, then declaration.

This is the library half of ``receipt verify``. It composes modules that were
each extracted under their own differential harness — it introduces no new
cryptography and no new trust anchors — and it enforces one rule the individual
modules cannot enforce on their own:

    A gate the command did not re-run is never reported as verified.

The three passes, in the order a skeptic should want them:

1. **Custody** (:mod:`receipt.release_chain`) — the release manifests are
   contiguous from genesis, canonically serialized, hash-linked, signed by the
   Ed25519 key selected by the loaded spec, and witnessed by the anchor set the
   verified tree carries. Those become auditor-owned pins only when the spec's
   source digest was itself pinned. The journal's historical byte prefixes
   match every manifest that ever described them.

2. **Binding** (:mod:`receipt.corpus`) — the journal the chain just proved
   custody of describes *this* tree, closed-world: every content file bound,
   every bound file present, every digest exact.

3. **Declaration** — the gates recorded in the journal are separated by
   reproducibility tier and reported as claims, per axiom-encode#1192
   requirement 6. Passing this pass means the declarations are well formed and
   cover what the consumer's spec requires. It does not mean the gates passed.

A verdict is fail-closed in the strict sense: it is ``PASS`` only if passes 1
and 2 both completed without raising and pass 3 found every required
declaration. Anything else — including an exception this module did not
anticipate, and including ``SystemExit``, which is not an ``Exception`` and
once unwound straight out of the interpreter from inside a consumer's spec —
is ``FAIL``. Only ``KeyboardInterrupt`` passes through: the operator
interrupted the run, and that is not a verdict about the corpus.
"""

from __future__ import annotations

import hashlib
import pathlib
import tempfile
from contextlib import ExitStack
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any

from receipt import __version__, snapshot as snapshot_module
from receipt.protected_tree import POLICY_VERSION, ProtectionPlan, TreePolicy, classify_mode, attribute_error
from receipt.corpus import (
    CI_ATTESTED_TIER,
    GATE_TIERS,
    PUBLIC_TIER,
    RESTRICTED_TIER,
    CorpusError,
    CorpusSpec,
    CorpusVerification,
    MAX_JOURNAL_BYTES,
    verify_corpus_binding,
    verify_declarations,
)
from receipt.release_chain import (
    ChainSpec,
    ChainVerification,
    ReleaseChainError,
    _normalized_spec,
    _screen_protected_tree_names,
    _protected_name_error,
    _base_shape_error,
    assert_no_redirecting_git_environment,
    verify_release_chain,
    verify_release_history_immutable,
)
from receipt.snapshot import ObjectStoreReport, SnapshotError, TreeSnapshot

#: What each tier means to a third party, in the verdict's own words. Stated
#: once, here, so the CLI cannot drift into a friendlier phrasing.
TIER_MEANING = {
    PUBLIC_TIER: "you can re-run these yourself from public inputs",
    RESTRICTED_TIER: "reproducible only with restricted pinned inputs this "
    "command cannot obtain",
    CI_ATTESTED_TIER: "not reproducible; only the CI run's identity vouches",
}


class VerifySpecError(ValueError):
    """The loaded verification spec is missing, malformed, or not a spec."""


def _custody_state_error(finding) -> ReleaseChainError:
    if finding.kind == "missing":
        return ReleaseChainError(f"state file is missing or not a regular file: {finding.path}")
    if finding.kind == "symlink":
        return ReleaseChainError(f"state file is a symlink: {finding.path}")
    return ReleaseChainError(f"state file is not a regular file: {finding.path}")


def _exception_detail(exc: BaseException) -> str:
    """Quote a failure, naming anything that is not an ordinary exception.

    ``str(SystemExit(0))`` is the bare string ``"0"``, which inside a refusal
    reads as a stray token rather than as a spec that tried to exit the
    interpreter. Ordinary exceptions already carry their own message and are
    quoted unchanged.
    """

    if isinstance(exc, Exception):
        return str(exc)
    return f"{type(exc).__name__}: {exc}"


#: The passes a PASS verdict is made of. A verdict is a claim about custody,
#: binding, and declaration; a result missing any of them has no verdict to
#: report, whatever else it recorded. Named here so ``ok`` states the
#: requirement rather than inferring it from whatever happened to run.
REQUIRED_PASSES = ("custody", "binding", "declaration")

#: What each completed pass establishes, in the verdict's own words. Keyed by
#: pass name so the JSON scope block can be built from actual results.
_PASS_CLAIMS = {
    "history": "that every release object present at the given base ref is "
    "byte- and mode-identical in this tree (objects added after that ref are "
    "outside this claim)",
    "custody": "custody of the release chain",
    "binding": "binding of the witnessed journal to tree {tree}",
}


@dataclass(frozen=True)
class VerificationSpec:
    """Everything one loaded verification policy binds, in one object.

    A repository publishes exactly one of these in a short module of constants.
    It is the whole configured trust surface: there is nowhere else for an
    anchor to hide. An auditor makes it trusted by reviewing and pinning the
    module's source digest before execution.
    """

    name: str
    chain: ChainSpec
    corpus: CorpusSpec
    anchor_set_sha256: str | None = None
    # Derived, never supplied: init=False so a consumer cannot even appear to
    # set it. See __post_init__ for why it is not a choice.
    journal_relative: pathlib.PurePosixPath = field(init=False, default=None)  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if type(self.name) is not str or not self.name:
            raise VerifySpecError("VerificationSpec name must be a non-empty string")
        if not isinstance(self.chain, ChainSpec):
            raise VerifySpecError("VerificationSpec chain must be a ChainSpec")
        if not isinstance(self.corpus, CorpusSpec):
            raise VerifySpecError("VerificationSpec corpus must be a CorpusSpec")
        if self.anchor_set_sha256 is not None and (
            type(self.anchor_set_sha256) is not str
            or len(self.anchor_set_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.anchor_set_sha256)
        ):
            raise VerifySpecError(
                "VerificationSpec anchor_set_sha256 must be a lowercase SHA-256 "
                f"digest or None: {self.anchor_set_sha256!r}"
            )
        # The journal the corpus binds IS the state file the chain witnesses.
        # Allowing them to differ would let a repository witness one file and
        # bind another, which is precisely the substitution the chain exists to
        # prevent, so it is not configurable.
        object.__setattr__(self, "journal_relative", self.chain.state_relative)


@dataclass(frozen=True, init=False)
class LoadedSpec:
    """A validated spec together with the exact source bytes that selected it.

    Instances come only from :func:`load_spec`: accepting arbitrary caller-built
    instances would let ``pinned=True`` become an assertion instead of evidence
    that this loader compared the source digest before executing the spec.
    """

    verification: VerificationSpec
    path: pathlib.Path
    sha256: str
    pinned: bool

    def __new__(cls, *args: object, **kwargs: object) -> LoadedSpec:
        del args, kwargs
        raise TypeError("LoadedSpec instances are created by load_spec")


@dataclass(frozen=True)
class PassResult:
    name: str
    ok: bool
    detail: str
    failure: str | None = None


@dataclass(frozen=True)
class VerifyResult:
    spec_name: str
    spec_path: pathlib.Path
    spec_sha256: str
    root: pathlib.Path
    receipt_version: str
    producer_spki_sha256: str
    passes: tuple[PassResult, ...]
    chain: ChainVerification | None
    corpus: CorpusVerification | None
    #: The selected, authenticated candidate identity. Both are None only
    #: when snapshot selection itself refused before an identity existed.
    commit: str | None = None
    tree: str | None = None
    object_format: str | None = None
    #: The full object id ``--base-ref`` resolved to, or None when no base ref
    #: was supplied. A ref spelling is not evidence: "HEAD", a branch name, or
    #: a tag names whatever it points at when the command runs, and the same
    #: verdict text is reproducible at a later commit. The commit is.
    base_commit: str | None = None
    base_tree: str | None = None
    name_repertoire: str = "portable"
    object_store: ObjectStoreReport | None = None
    _spec_pinned: bool = field(default=False, repr=False)
    #: Whether the caller asked for whole-store verification. A missing report
    #: on a failed run must not be rendered as "not requested".
    _object_store_requested: bool = field(default=False, repr=False)
    #: Whether custody's anchor-set digest was compared with an auditor-owned
    #: pin. Private because it qualifies a claim rather than adding another
    #: public datum to the result contract.
    _anchor_set_pinned: bool = field(default=False, repr=False)

    @property
    def ok(self) -> bool:
        """Every recorded pass succeeded, and the three that make a verdict ran.

        ``all()`` on its own is vacuously true. A result carrying no passes —
        a run that fell over before reaching the first one, or a result built
        by a caller composing this library — reported PASS, and the command
        printed "ESTABLISHED OFFLINE, FROM THIS CLONE ALONE" and exited 0 over
        an empty list of passes. Absence of a failure is not the same as
        presence of a verdict, so the required passes are named and checked.
        """

        completed = {item.name for item in self.passes if item.ok}
        return all(item.ok for item in self.passes) and completed.issuperset(
            REQUIRED_PASSES
        )

    @property
    def head_name(self) -> str | None:
        if self.chain is None or self.chain.head is None:
            return None
        return self.chain.head.path.name

    @property
    def anchor_set_sha256(self) -> str | None:
        """One digest naming the anchor bytes custody consumed.

        Captured at the read sites signature and receipt verification used
        (OpenSSL is fed a snapshot of those exact bytes), under this
        command's unconditional production pins. Pin semantics differ by
        role: TSA anchor bytes are spec-bound exactly, while producer identity
        is bound by SPKI — a byte-different serialization of the
        same producer key verifies and is recorded at its own digest here.
        None unless custody completed successfully.
        """
        if self.chain is None:
            return None
        return self.chain.anchor_set_sha256

    @property
    def anchor_file_sha256s(self) -> dict[str, str]:
        """The per-file digests behind anchor_set_sha256, keyed by the
        spec's configured filename strings; empty unless custody completed
        successfully."""
        if self.chain is None:
            return {}
        return dict(self.chain.anchor_file_sha256s)

    def witness_times(self) -> dict[str, datetime]:
        if self.chain is None or self.chain.head is None:
            return {}
        return dict(self.chain.head.receipt_times)


def load_spec(
    spec_path: pathlib.Path, *, expect_sha256: str | None = None
) -> LoadedSpec:
    """Load a consumer spec, optionally requiring its exact source digest.

    The spec is Python because the package's trust anchors are Python objects;
    it is expected to be a short module of constants. Executing it is a
    deliberate part of the model — an auditor is verifying a repository they
    have already cloned, and the spec's own SHA-256 is returned so the exact
    configuration a verdict was produced under can be quoted and re-pinned.

    Trust direction, stated plainly: a spec committed in the *producer's*
    repository is the producer's proposal, not the auditor's trust root.
    Verified against a producer-shipped spec as found, a verdict establishes
    only internal consistency with a policy the producer chose. For independent
    custody the auditor reads the spec once, out of band, and pins it — at
    minimum the ``spec_sha256`` this function returns — in the auditor's own
    records, after which every later verdict is against anchors the producer
    cannot silently swap. Reading the spec is part of that one-time review;
    a future inert, schema-validated spec format would remove even the need to
    execute it, and is tracked as follow-up work.

    The path's final component is required to be a regular file, not a
    symlink to one, checked as supplied rather than after resolution: a link
    can be repointed at other bytes without the path the auditor pinned
    changing at all. Parent components are not walked. An absolute path
    legitimately crosses ambient links (``/tmp`` on macOS), and the
    component walk the anchor check does runs under a resolved root, which a
    spec path does not have; a symlinked parent of the spec is therefore not
    caught here, and the same final-component rule governs every other read
    in the package.

    The source is read once and compiled from those exact bytes, deliberately
    bypassing the import system. Going through ``importlib`` would consult
    ``__pycache__``, whose staleness check is (source mtime, source size) at
    one-second granularity — so an edited spec restored within the same second,
    to a file of the same length, keeps executing the edited bytecode. The
    digest reported beside the verdict would then describe a file that was not
    the one used to verify. Compiling the hashed bytes makes the two identical
    by construction. When ``expect_sha256`` is supplied, its comparison happens
    immediately after hashing and before either compiling or executing those
    bytes; a mismatched spec therefore has no opportunity to run.
    """

    import types

    if expect_sha256 is not None and (
        type(expect_sha256) is not str
        or len(expect_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expect_sha256)
    ):
        raise VerifySpecError(
            "expected spec SHA-256 must be a lowercase 64-character hex digest"
        )

    # Before resolving, deliberately. Every other read in this package refuses
    # a symlink in the final component — manifests, receipts, anchors, the
    # witnessed journal — and the
    # spec is the trust configuration itself, so it gets the same treatment.
    # The check ran after ``resolve()``, which follows every link on the way,
    # so nothing was ever left for it to catch. A symlink also breaks the one
    # thing an auditor pins: they read the spec out of band and record its
    # digest against a path, and the link can be repointed at other bytes
    # afterwards without that path changing at all.
    # M1 record, executable-spec paragraph: physical user input is outside the Git tree.
    if spec_path.is_symlink():
        raise VerifySpecError(
            f"spec is a symlink; supply the regular file's path: {spec_path}"
        )
    spec_path = spec_path.resolve()
    if spec_path.is_symlink() or not spec_path.is_file():
        raise VerifySpecError(f"spec is missing or not a regular file: {spec_path}")
    source = spec_path.read_bytes()
    digest = hashlib.sha256(source).hexdigest()
    if expect_sha256 is not None and digest != expect_sha256:
        raise VerifySpecError(
            f"spec {digest} is not the expected spec {expect_sha256}"
        )

    module = types.ModuleType("_receipt_consumer_spec")
    module.__file__ = str(spec_path)
    try:
        code = compile(source, str(spec_path), "exec")
        exec(code, module.__dict__)  # noqa: S102 - the audited repo's own pins
    except KeyboardInterrupt:  # the operator's interrupt, never a verdict
        raise
    except BaseException as exc:  # noqa: BLE001 - any failure here is fail-closed
        # BaseException deliberately, not Exception. A spec containing
        # ``raise SystemExit(0)`` unwound straight through an Exception-only
        # boundary, past every pass below, and out of the interpreter with
        # status 0 and no verdict printed at all — the producer's own spec
        # choosing the command's exit code. SystemExit and GeneratorExit are
        # load failures like any other; only the operator's interrupt is
        # allowed through, because it is not the spec's to report.
        raise VerifySpecError(
            f"spec module raised on load: {spec_path}: {_exception_detail(exc)}"
        ) from exc

    candidate = getattr(module, "SPEC", None)
    if candidate is None:
        raise VerifySpecError(
            f"spec module does not define SPEC: {spec_path}"
        )
    if not isinstance(candidate, VerificationSpec):
        raise VerifySpecError(
            f"SPEC is {type(candidate).__name__}, not a receipt.verify."
            f"VerificationSpec: {spec_path}"
        )
    loaded = object.__new__(LoadedSpec)
    object.__setattr__(loaded, "verification", candidate)
    object.__setattr__(loaded, "path", spec_path)
    object.__setattr__(loaded, "sha256", digest)
    object.__setattr__(loaded, "pinned", expect_sha256 is not None)
    return loaded


def _witness_time(value: datetime) -> str:
    """Render a witnessed genTime without discarding what the token signed.

    An RFC 3161 authority may sign a fractional genTime, and whole-second
    formatting printed a token witnessed at ``…:59.750000Z`` as ``…:59Z`` —
    an instant strictly earlier than the one the receipt carries, quoted in a
    verdict as though it were exact. Microseconds are printed whenever there
    are any; when there are none they are omitted, so the ordinary case reads
    as the authority wrote it.
    """

    if value.microsecond:
        return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _custody_detail(verification: ChainVerification, spec: VerificationSpec) -> str:
    head = verification.head
    assert head is not None
    witnesses = " · ".join(
        f"{anchor} {_witness_time(value)}"
        for anchor, value in sorted(head.receipt_times.items())
    )
    anchor_set = verification.anchor_set_sha256
    assert anchor_set is not None
    return (
        f"{len(verification.releases)} release(s), HEAD {head.path.name}; "
        # The filename carries only the first 16 hex of the head manifest's
        # digest, and that digest is exactly the value an auditor compares out
        # of band — freshness and uniqueness are the two things this command
        # states it cannot establish from one clone, and comparing head
        # digests is the remedy it names for both. A prefix is not quotable
        # evidence for that comparison, so the full digest gets its own
        # segment beside the filename an auditor can find on disk.
        f"head {head.sha256}; "
        f"producer SPKI {spec.chain.producer_spki_sha256[:16]}…; "
        # Full digest, deliberately: the anchor-set digest exists so an
        # assessment can quote it from the verdict alone, and unlike the
        # SPKI it is pinned nowhere else. A prefix would not be quotable
        # evidence.
        f"anchor set {anchor_set}; "
        f"witnesses {witnesses}"
    )


def _binding_detail(verification: CorpusVerification) -> str:
    removed = len(verification.removed_paths)
    removed_text = f", {removed} superseded-removed" if removed else ""
    return (
        f"{len(verification.content)} content file(s) and "
        f"{len(verification.attested)} attested file(s) match the witnessed "
        f"journal exactly, closed-world{removed_text}"
    )


def _declaration_detail(verification: CorpusVerification) -> str:
    if not verification.gates:
        return "no gate declarations in the journal"
    counts = []
    for tier in GATE_TIERS:
        gates = verification.gates_in_tier(tier)
        if gates:
            counts.append(f"{len(gates)} {tier}")
    return (
        f"{len(verification.gates)} gate declaration(s) well formed and complete "
        f"against the loaded spec ({', '.join(counts)}); none re-run here"
    )


# M1 record, verify row 658-709; PR3a/PR5: retain every substituted-reader facade branch.
def run_verification(
    root: pathlib.Path,
    spec: LoadedSpec,
    *,
    base_ref: str | None = None,
    commit: str = "HEAD",
    expect_commit: str | None = None,
    expect_tree: str | None = None,
    expect_anchor_set: str | None = None,
    verify_objects: bool = False,
) -> VerifyResult:
    """Verify one authenticated commit, stopping at the first failed pass.

    Verification failures are returned, never raised. Entry-contract
    violations are different: comparing history without pinning the candidate,
    presenting an anchor pin without first pinning the executable spec, or
    declaring two name repertoires raises :class:`ValueError`.

    The 0.5.2 refusal of redirecting Git environment variables is deliberately
    retained before snapshot selection. The underlying ``TreeSnapshot`` reader
    remains invariant under those variables through its frozen Git environment
    and explicit repository selection.
    """

    if not isinstance(spec, LoadedSpec):
        raise TypeError("spec must be a LoadedSpec returned by load_spec")
    if base_ref is not None and expect_commit is None:
        raise ValueError("base_ref requires expect_commit")

    verification_spec = spec.verification
    chain_repertoire = verification_spec.chain.name_repertoire
    corpus_repertoire = verification_spec.corpus.name_repertoire
    if chain_repertoire != corpus_repertoire:
        raise ValueError("spec declares two name repertoires")

    spec_anchor_pin = verification_spec.anchor_set_sha256
    if expect_anchor_set is not None and not spec.pinned:
        raise ValueError("an anchor pin requires a pinned spec")
    if expect_anchor_set is not None and (
        type(expect_anchor_set) is not str
        or len(expect_anchor_set) != 64
        or any(character not in "0123456789abcdef" for character in expect_anchor_set)
    ):
        raise ValueError(
            "expected anchor-set SHA-256 must be a lowercase 64-character hex digest"
        )
    anchor_pin_conflict = (
        expect_anchor_set is not None
        and spec_anchor_pin is not None
        and expect_anchor_set != spec_anchor_pin
    )
    anchor_pin = (
        expect_anchor_set if expect_anchor_set is not None else spec_anchor_pin
    ) if spec.pinned else None

    root = root.resolve()
    passes: list[PassResult] = []
    chain: ChainVerification | None = None
    corpus: CorpusVerification | None = None
    candidate_commit: str | None = None
    candidate_tree: str | None = None
    object_format: str | None = None
    base_commit: str | None = None
    base_tree: str | None = None
    object_store: ObjectStoreReport | None = None

    def result(*, incomplete: str | None = None) -> VerifyResult:
        items = list(passes)
        if incomplete is not None:
            items.append(PassResult(incomplete, False, "", "not reached"))
        return VerifyResult(
            spec_name=verification_spec.name,
            spec_path=spec.path,
            spec_sha256=spec.sha256,
            root=root,
            receipt_version=__version__,
            producer_spki_sha256=verification_spec.chain.producer_spki_sha256,
            passes=tuple(items),
            chain=chain,
            corpus=corpus,
            commit=candidate_commit,
            tree=candidate_tree,
            object_format=object_format,
            base_commit=base_commit,
            base_tree=base_tree,
            name_repertoire=chain_repertoire,
            object_store=object_store,
            _spec_pinned=spec.pinned,
            _object_store_requested=verify_objects,
            _anchor_set_pinned=anchor_pin is not None,
        )

    # Every pass — the verification call AND the detail builder that reports
    # it — runs inside a boundary that converts *any* raise, expected or not,
    # into a failed pass. The documented contract is that a verification
    # failure is the return value and never an escaping exception (so a --json
    # consumer always receives a {"verdict": "FAIL"} object); an unforeseen
    # exception here would otherwise leave the CLI to exit 1 with no verdict at
    # all. The boundaries below catch BaseException rather than Exception,
    # because SystemExit is neither: raised anywhere under a pass it unwound
    # past an Exception-only boundary and out of the interpreter, choosing the
    # command's exit status with no verdict printed. KeyboardInterrupt alone is
    # re-raised — it is the operator's, not the verification's, to report.
    # Expected domain errors carry their own message; anything else names its
    # type so the surprise is legible.
    def failed(
        name: str,
        exc: BaseException,
        expected: type[Exception] | tuple[type[Exception], ...],
    ) -> str:
        del name
        if isinstance(exc, expected):
            return str(exc)
        return f"{type(exc).__name__}: {exc}"

    # Before any pass runs git: an environment that would redirect git's reads
    # is refused here rather than met by the custody pass after the optional
    # history pass has already resolved a base and printed an OID from
    # whichever repository the environment pointed at (peer review of the
    # 0.5.2 release PR). It is reported as the custody pass's refusal, in that
    # pass's own words, so the verdict reads the same with or without
    # ``--base-ref``.
    try:
        assert_no_redirecting_git_environment()
    except KeyboardInterrupt:  # the operator's interrupt, never a verdict
        raise
    except BaseException as exc:  # noqa: BLE001 - any raise is a FAIL verdict
        passes.append(
            PassResult("custody", False, "", failed("custody", exc, ReleaseChainError))
        )
        return result(incomplete="binding")

    if anchor_pin_conflict:
        passes.append(
            PassResult(
                "custody",
                False,
                "",
                "anchor pins disagree: "
                f"command expects {expect_anchor_set}, spec expects {spec_anchor_pin}",
            )
        )
        return result(incomplete="binding")

    phase = "custody"
    try:
        # A single normalized ChainSpec instance is shared by the pre-crypto
        # anchor digest and the directory verifier. Stateful PathLike values
        # cannot answer those two consumers with different spellings.
        normalized_chain = _normalized_spec(verification_spec.chain)
        selected = TreeSnapshot.select(
            root,
            commit,
            verify_objects=verify_objects,
            expect_commit=expect_commit,
            expect_tree=expect_tree,
        )
        candidate_commit = selected.commit
        candidate_tree = selected.tree
        object_format = selected.object_format

        with ExitStack() as stack:
            candidate = stack.enter_context(selected)
            base: TreeSnapshot | None = None
            if base_ref is not None:
                phase = "history"
                base = stack.enter_context(TreeSnapshot.select(root, base_ref))
                base_commit = base.commit
                base_tree = base.tree
                candidate.assert_ancestor(base)

            # Object-store verification is about the primary store, not one
            # logical pass, and runs over exactly the already-resolved heads.
            if verify_objects:
                phase = "custody"
                heads = (
                    (candidate.commit,)
                    if base is None
                    else (candidate.commit, base.commit)
                )
                object_store = candidate.verify_object_store(heads)

            # Pass 0 (optional): history comparison consumes tree entries only.
            if base is not None:
                phase = "history"
                verify_release_history_immutable(
                    normalized_chain,
                    candidate=candidate,
                    base=base,
                )
                passes.append(
                    PassResult(
                        "history",
                        True,
                        f"every release object present at {base_ref} "
                        f"({base.commit}) is byte- and mode-identical in tree "
                        f"{candidate.tree[:12]}",
                    )
                )

            phase = "custody"

            prefixes = (
                normalized_chain.release_root_relative,
                normalized_chain.manifest_relative,
                normalized_chain.state_relative,
                normalized_chain.prefix_relative,
                normalized_chain.anchor_relative,
            )
            # Keep the existing replaceable reader protocol used by composition
            # callers. Only the concrete authenticated reader can issue views;
            # supplied mappings remain compatibility evidence, never authority.
            policy = (TreePolicy(candidate, policy_version=POLICY_VERSION, work=candidate.work)
                      if type(candidate) is snapshot_module.TreeSnapshot else None)
            custody_plan = ProtectionPlan.chain_names(
                prefixes,
                repertoire=chain_repertoire,
                release_directories=(
                    normalized_chain.release_root_relative,
                    normalized_chain.manifest_relative,
                ),
                use="custody", anchor_origin="tree",
            )
            if policy is None:
                _screen_protected_tree_names(
                    candidate.entries("").as_dict(include_trees=True), prefixes,
                    repertoire=chain_repertoire,
                    release_directories=(normalized_chain.release_root_relative,
                                         normalized_chain.manifest_relative),
                )
            else:
                names = policy.evaluate(custody_plan, stage="suffixes")
                names.require(custody_plan.use, render=_protected_name_error)

            def state_blob(relative: pathlib.PurePosixPath) -> bytes:
                display = relative.as_posix()
                try:
                    entry = candidate.entry(display)
                except SnapshotError as exc:
                    if str(exc) == f"tree entry does not exist: {display}":
                        raise ReleaseChainError(
                            f"state file is missing or not a regular file: {display}"
                        ) from exc
                    raise
                if policy is None:
                    # The legacy state protocol exposes mode only. This does
                    # not bind an object type or authorize a Git payload read.
                    finding = classify_mode(entry.mode, "blob").finding(display, "state-leaf")
                    if finding is not None:
                        raise _custody_state_error(finding)
                    return candidate.blob(entry, limit=MAX_JOURNAL_BYTES)
                policy.observe_entries((entry,))
                state_plan = replace(custody_plan, obligations=("modes",), listing_scope=(),
                                     mode_roles=((display, "state-leaf"),), phase="state")
                state = policy.evaluate(state_plan, stage="modes")
                selection = state.require(state_plan.use, render=_custody_state_error)
                selected = selection.entries_for(candidate, use=state_plan.use, plan=state_plan)
                return candidate.blob(selected[display], limit=MAX_JOURNAL_BYTES)

            journal_bytes = state_blob(verification_spec.journal_relative)
            prefix_bytes = state_blob(normalized_chain.prefix_relative)
            state_bytes = {
                verification_spec.journal_relative.as_posix(): journal_bytes,
                normalized_chain.prefix_relative.as_posix(): prefix_bytes,
            }
            with tempfile.TemporaryDirectory(
                prefix="receipt-verification-materialization-"
            ) as directory:
                with candidate.materialize(
                    prefixes,
                    pathlib.Path(directory),
                    repertoire=chain_repertoire,
                ) as materialized:
                    # Selection and its admission/refusal schedule remain in
                    # the materializer facade for PR3b. Consume its actual
                    # paths, including the effect of overlapping prefixes.
                    materialized_entries = materialized.entries
                    if policy is not None:
                        selected_paths = tuple(sorted(materialized_entries))
                        shape_plan = replace(custody_plan, obligations=("ancestors", "modes"),
                                             ancestor_paths=selected_paths,
                                             mode_roles=tuple((p, "export-leaf") for p in selected_paths))
                        shapes = policy.evaluate(shape_plan, stage="modes")
                        shapes.require(shape_plan.use, render=_base_shape_error)
                    if policy is None:
                        candidate.refuse_transforming_attributes(materialized_entries.values())
                    else:
                        attribute_plan = replace(custody_plan, obligations=("attributes",),
                            listing_scope=(), phase="attributes", attribute_target_selectors=tuple(
                                entry.path for entry in materialized_entries.values()))
                        attributes = policy.evaluate_attributes(attribute_plan)
                        attributes.require(attribute_plan.use, render=attribute_error)
                    materialized_anchor_set = materialized.anchor_set_sha256(
                        normalized_chain
                    )
                    if (
                        anchor_pin is not None
                        and materialized_anchor_set != anchor_pin
                    ):
                        raise ReleaseChainError(
                            f"anchor set {materialized_anchor_set} is not the "
                            f"pinned anchor set {anchor_pin}"
                        )
                    chain = verify_release_chain(
                        materialized.path,
                        spec=normalized_chain,
                        require_chain=True,
                        verify_state=True,
                        enforce_production_pins=True,
                        compute_anchor_set_digest=True,
                        state_bytes=state_bytes,
                    )
                    if chain.anchor_set_sha256 != materialized_anchor_set:
                        raise ReleaseChainError(
                            f"verified anchor set {chain.anchor_set_sha256} is not "
                            f"the materialized anchor set {materialized_anchor_set}"
                        )
                    custody_detail = _custody_detail(chain, verification_spec)
            passes.append(PassResult("custody", True, custody_detail))

            # Pass 2: the immutable journal blob already supplied to custody is
            # handed to binding. Its SHA-256 is repeated against the witnessed
            # value so the composition remains explicit and independently
            # reviewable even though an immutable snapshot cannot race itself.
            phase = "binding"
            head = chain.head
            assert head is not None
            witnessed_digest = head.manifest["state"]["jsonlSha256"]
            actual_digest = hashlib.sha256(journal_bytes).hexdigest()
            if actual_digest != witnessed_digest:
                raise CorpusError(
                    "journal bytes do not match the custody pass: "
                    f"{actual_digest} != witnessed {witnessed_digest}"
                )
            from receipt import corpus as corpus_module

            if policy is None or verify_corpus_binding is not corpus_module._VERIFY_CORPUS_BINDING_ORIGINAL:
                corpus = verify_corpus_binding(
                    candidate, journal_bytes, spec=verification_spec.corpus)
            else:
                corpus = corpus_module._verify_corpus_binding(
                    candidate, journal_bytes, spec=verification_spec.corpus, policy=policy)
            binding_detail = _binding_detail(corpus)
            passes.append(PassResult("binding", True, binding_detail))

            # Pass 3: declarations are claims recorded in the authenticated
            # journal, not gates this command re-runs.
            phase = "declaration"
            verify_declarations(corpus, spec=verification_spec.corpus)
            declaration_detail = _declaration_detail(corpus)
            passes.append(PassResult("declaration", True, declaration_detail))
            phase = "finalize"
    except KeyboardInterrupt:  # the operator's interrupt, never a verdict
        raise
    except BaseException as exc:  # noqa: BLE001 - every other raise is a FAIL
        if phase == "history":
            passes.append(
                PassResult(
                    "history",
                    False,
                    "",
                    "release history is not immutable: "
                    f"{failed('history', exc, (ReleaseChainError, SnapshotError))}",
                )
            )
            return result(incomplete="custody")
        if phase in {"custody", "finalize"}:
            # A close-time repository re-audit invalidates every tree-derived
            # pass even if its body happened to finish first.
            passes[:] = [item for item in passes if item.name == "history"]
            chain = None
            corpus = None
            passes.append(
                PassResult(
                    "custody",
                    False,
                    "",
                    failed("custody", exc, (ReleaseChainError, SnapshotError)),
                )
            )
            return result(incomplete="binding")
        if phase == "binding":
            corpus = None
            passes.append(
                PassResult(
                    "binding",
                    False,
                    "",
                    failed("binding", exc, (CorpusError, SnapshotError)),
                )
            )
            return result(incomplete="declaration")
        assert phase == "declaration"
        passes.append(
            PassResult(
                "declaration",
                False,
                "",
                failed("declaration", exc, CorpusError),
            )
        )
        return result()
    return result()


def result_to_dict(result: VerifyResult) -> dict[str, Any]:
    """Machine-readable verdict, including the text's three object-store states.

    ``objectStore: null`` means verification was not requested, a requested
    run that did not complete carries ``requested: true`` with a null report,
    and a completed run carries the measured report.
    """

    def established_claim(item: PassResult) -> str:
        if item.name == "binding":
            assert result.tree is not None
            return _PASS_CLAIMS["binding"].format(tree=result.tree[:12])
        if item.name == "custody" and not result._anchor_set_pinned:
            anchor_set = result.anchor_set_sha256
            assert anchor_set is not None
            return (
                f"custody under the anchor set {anchor_set} the verified tree "
                "carries"
            )
        return _PASS_CLAIMS[item.name]

    base: dict[str, str] | None = None
    if result.base_commit is not None:
        assert result.base_tree is not None
        base = {"commit": result.base_commit, "tree": result.base_tree}
    object_store: dict[str, Any] | None = None
    if result.object_store is not None:
        object_store = {
            "objects": result.object_store.objects,
            "storeKiB": result.object_store.store_kib,
            "seconds": result.object_store.seconds,
        }
    elif result._object_store_requested:
        object_store = {"requested": True, "report": None}

    not_established = [
        "that any declared gate actually passed",
        "that the encoded rules are a correct reading of the law",
        "that this clone holds the producer's newest release "
        "(--base-ref only bounds staleness against a head the auditor "
        "recorded; newest needs an out-of-band comparison)",
        "that this is the only history the producer maintains "
        "(equivocation is undetectable from a single clone; compare "
        "head digests out of band)",
        "that the files in any checkout equal the verified tree",
    ]
    if not result._anchor_set_pinned:
        not_established.append("that the anchor set is one the auditor trusts")
    if not result._spec_pinned:
        not_established.append("that the spec's code was trusted")

    payload: dict[str, Any] = {
        "verdict": "PASS" if result.ok else "FAIL",
        # Named for what it is: passes that completed. "verifiedOffline" would
        # invite a reader to hear "the gates were verified", which is the one
        # thing this command never does.
        "passesCompleted": [item.name for item in result.passes if item.ok],
        "spec": {
            "name": result.spec_name,
            "path": str(result.spec_path),
            "sha256": result.spec_sha256,
            "pinned": result._spec_pinned,
        },
        "root": str(result.root),
        "commit": result.commit,
        "tree": result.tree,
        "objectFormat": result.object_format,
        "base": base,
        "nameRepertoire": result.name_repertoire,
        "objectStore": object_store,
        "receiptVersion": result.receipt_version,
        "passes": [
            {
                "name": item.name,
                "ok": item.ok,
                "detail": item.detail,
                "failure": item.failure,
            }
            for item in result.passes
        ],
        "scope": {
            # Built from the passes that actually completed — a FAIL run must
            # not carry a field named "established" listing things it did not
            # establish (cross-family review finding).
            "established": [
                established_claim(item)
                for item in result.passes
                if item.ok and item.name in _PASS_CLAIMS
            ],
            "notEstablished": not_established,
        },
    }
    if result.base_commit is not None:
        # The object id the comparison actually ran against. The ref spelling
        # stays in the history pass detail beside it; only one of the two is
        # evidence a reader can re-check.
        payload["history"] = {
            "baseCommit": result.base_commit,
            "baseTree": result.base_tree,
        }
    if result.chain is not None and result.chain.head is not None:
        payload["chain"] = {
            "releases": len(result.chain.releases),
            "head": result.chain.head.path.name,
            "headSha256": result.chain.head.sha256,
            "producerSpkiSha256": result.producer_spki_sha256,
            # Which anchor bytes this run consumed, from the verdict alone:
            # digests captured at the verification read sites themselves,
            # with the per-file digests behind the combined one (receipt#24).
            "anchorSetSha256": result.chain.anchor_set_sha256,
            "anchorFiles": dict(result.chain.anchor_file_sha256s),
            "witnesses": {
                anchor: _witness_time(value)
                for anchor, value in sorted(result.chain.head.receipt_times.items())
            },
        }
    if result.corpus is not None:
        payload["binding"] = {
            "contentFiles": len(result.corpus.content),
            "attestedFiles": len(result.corpus.attested),
            "removedPaths": list(result.corpus.removed_paths),
        }
        payload["gateDeclarations"] = {
            "reRunByThisCommand": False,
            "byTier": {
                tier: [
                    {
                        "gateId": gate.gate_id,
                        "outcome": gate.outcome,
                        "evidence": dict(gate.evidence),
                    }
                    for gate in result.corpus.gates_in_tier(tier)
                ]
                for tier in GATE_TIERS
                if result.corpus.gates_in_tier(tier)
            },
            "tierMeaning": {
                tier: TIER_MEANING[tier]
                for tier in GATE_TIERS
                if result.corpus.gates_in_tier(tier)
            },
        }
    return payload
'''
# END verbatim src/receipt/verify.py


def function_hashes(source):
    """Hash exact source spans, including indentation and decorators."""
    lines = source.splitlines(keepends=True)
    result = {}
    def visit(nodes, parent=""):
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = parent + node.name
                if not isinstance(node, ast.ClassDef):
                    start = min([node.lineno] + [d.lineno for d in node.decorator_list])
                    body = "".join(lines[start - 1:node.end_lineno])
                    result[name] = hashlib.sha256(body.encode()).hexdigest()
                visit(node.body, name + ".")
    visit(ast.parse(source).body)
    return result


@lru_cache(maxsize=1)
def authenticate():
    """Refuse a missing/changed local oracle before any old/live comparison."""
    sources = {}
    for path, digest in SOURCE_SHA256.items():
        original = subprocess.run(
            ["git", "show", f"{MEASURED_SHA}:{path}"], cwd=ROOT,
            capture_output=True, check=True, timeout=30,
        ).stdout
        assert hashlib.sha256(original).hexdigest() == digest, path
        source = FROZEN_SOURCE.get(path, original.decode())
        assert source.encode() == original, path
        if path in BODY_SHA256:
            assert function_hashes(source) == BODY_SHA256[path], path
        sources[path] = source
    return sources


class _SourceTree(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def __init__(self, sources, label):
        self.sources, self.label = sources, label

    def find_spec(self, fullname, path=None, target=None):
        if fullname == "receipt":
            source = "src/receipt/__init__.py"
        elif fullname.startswith("receipt."):
            source = "src/" + fullname.replace(".", "/") + ".py"
        else:
            return None
        # No accidental live dependency fallback inside the frozen package.
        if source not in self.sources:
            raise ImportError(f"unfrozen receipt dependency: {fullname}")
        return importlib.util.spec_from_loader(
            fullname, self, origin=source, is_package=fullname == "receipt")

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        path = module.__spec__.origin
        source = self.sources[path]
        filename = f"<m3-{self.label}>/{path}"
        linecache.cache[filename] = (len(source), None, source.splitlines(True), filename)
        module.__file__ = str(ROOT / path)
        exec(compile(source, filename, "exec"), module.__dict__)


def _receipt_modules():
    return {k: v for k, v in sys.modules.items()
            if k == "receipt" or k.startswith("receipt.")}


@contextmanager
def source_tree(*, old, fresh=False):
    """Separate complete globals, preserving exact public exception class names.

    The swap is synchronous and confined to this context; callers retain their
    original live references. Tests never run concurrent legs. A fresh live tree
    also permits authentic pre-import substitution controls without subprocesses.
    """
    sources = authenticate()
    saved = _receipt_modules()
    if not old and not fresh:
        yield
        return
    if not old:
        sources = {p: (ROOT / p).read_text() for p in sources}
    for name in saved:
        del sys.modules[name]
    finder = _SourceTree(sources, MEASURED_SHA if old else "live")
    sys.meta_path.insert(0, finder)
    try:
        yield
    finally:
        sys.meta_path.remove(finder)
        for name in _receipt_modules():
            del sys.modules[name]
        sys.modules.update(saved)


def modules():
    return SimpleNamespace(**{name: importlib.import_module("receipt." + name)
        for name in ("snapshot", "protected_tree", "verify", "corpus",
                     "release_chain", "append_gate")})
